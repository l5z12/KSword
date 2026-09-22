#pragma once

// ============================================================
// ProcessDock.h
// Purpose:
// - Build the complete R3 Task Manager interface within the 'Process' Dock;
// - Provides capabilities for asynchronous refresh, tree/list views, column management, and right-click operations.
// - Decouple from the ks::process Win32 wrapper layer; the UI layer handles only display and interaction.
// ============================================================

#include "../Framework.h"
#include "../../../shared/ark_client/ArkDriverTypes.h"
#include "../../../shared/platform/process/ProcessCpuCoreEtwMonitor.h"

#include <QColor>
#include <QHash>
#include <QIcon>
#include <QList>
#include <QModelIndex>
#include <QPointer>
#include <QSet>
#include <QSize>
#include <QThreadPool>
#include <QVariant>
#include <QWidget>

#include <atomic>
#include <array>
#include <chrono>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

// Forward declarations: Reduce header file compilation overhead.
class QComboBox;
class QCheckBox;
class QDialog;
// DmaProcessOpPage appears by value in a member pointer, requiring a complete type.
#include "../memory_dock/DmaProcessOpPage.h"
class QDoubleSpinBox;
class QFormLayout;
class QGroupBox;
class QHeaderView;
class QImage;
class QLabel;
class QLineEdit;
class QPlainTextEdit;
class QPushButton;
class QResizeEvent;
class QShowEvent;
class QSlider;
class QSortFilterProxyModel;
class QTableWidget;
class QTableView;
class QTabWidget;
class QTextEdit;
class QTimer;
class QTreeWidget;
class QTreeWidgetItem;
class QVBoxLayout;
class QHBoxLayout;
class QPoint;
class QWidget;
class CodeEditorWidget;
class ProcessDetailWindow;
class ProcessActivityChartWidget;
class ProcessActivityTimelineSlider;

namespace ks::process
{
    struct CounterSample;
    struct ThreadCounterSample;
    struct ProcessRecord;
    struct SystemThreadRecord;
}

namespace ks::network
{
    class ProcessNetworkEtwMonitor;
}

namespace ks::ui
{
    template<typename RowT>
    class FlatTableModel;
}

class ProcessDock final : public QWidget
{
    Q_OBJECT
    friend class ProcessActivityChartWidget;
    friend class ProcessActivityTimelineSlider;

public:
    // Constructor purpose:
    // - initialize the sidebar tabs;
    // - initialize the process list and control bar.
    // - Start default monitoring (performance counter view).
    explicit ProcessDock(QWidget* parent = nullptr);

    // Destructor purpose:
    // - Remove the mouse event filter installed on QApplication during construction.
    // - Does not return a value to avoid receiving global click events after the Dock is destroyed.
    ~ProcessDock() override;

    // refreshThemeVisuals:
    // - Repaint the current list row coloring after switching between light and dark themes.
    // - Fix the issue where the highlight color for newly added processes remains after a theme switch.
    // Call pattern: mainWindow::applyAppearanceSettings invokes this after a theme update.
    // Input: None.
    // Returns: Nothing.
    void refreshThemeVisuals();

    // requestOpenProcessDetailByPid:
    // - External modules open process detail windows by PID.
    // - Reuse the existing window if it corresponds to the request; do not create a duplicate.
    // Invocation method: mainWindow/FileDock navigates to this entry point.
    // Parameter pid: Target process PID.
    // Returns: Nothing.
    void requestOpenProcessDetailByPid(std::uint32_t pid);

    // requestOpenProcessDetailByIdentity:
    // - Open the exact process instance using the PID + creation time saved from historical events;
    // - Invocation method: Called by the identity-aware jump slot of mainWindow;
    // - Input parameter pid: historical process PID;
    // - Input creationTime100ns: Process creation time captured at the moment;
    // - Return: None; explicitly prompt and refuse to open if the target has exited, is unverifiable, or the PID has been reused.
    void requestOpenProcessDetailByIdentity(
        std::uint32_t pid,
        std::uint64_t creationTime100ns);

signals:
    // requestFocusProcessProtectByCallback: The process page shortcut entry requests the main window to open the unified callback protection page.
    void requestFocusProcessProtectByCallback();

protected:
    // eventFilter:
    // - Capture mouse clicks within the process page;
    // - Clear the current process selection when clicking outside the process table or in empty areas, returning the activity graph to the overall view.
    // Parameter watched: event recipient object; event: Qt native event.
    // Return value: true indicates the event has been fully handled; false indicates continuing to the default Qt event flow.
    bool eventFilter(QObject* watched, QEvent* event) override;

    // showEvent:
    // - Start the initial refresh and periodic monitoring only when the Dock is first truly displayed.
    // - Avoid slowing down main window startup with process enumeration.
    void showEvent(QShowEvent* event) override;

    // resizeEvent:
    // - Request a one-time default column width adaptation for the process table when the Dock size changes.
    // - Do not force-hide the horizontal scrollbar; allow it to appear as needed after the user manually widens a column.
    // Invocation: Qt automatically triggers this when the window size changes.
    // Parameter event: Qt-provided resize event object (read-only use).
    // Return value: None.
    void resizeEvent(QResizeEvent* event) override;

private:
    // TableColumn: Uniformly defines table column indices to avoid hard-coded magic numbers.
    enum class TableColumn : int
    {
        kName = 0,      // Process name (with icon).
        kPid,           // PID。
        kCpu,           // CPU percentage.
        kRam,           // RAM（MB）。
        kDisk,          // DISK（MB/s）。
        kGpu,           // GPU percentage (R3 PDH GPU Engine aggregation).
        kNet,           // Net (reserved).
        kSignature,     // Digital signature status.
        kPath,          // Executable path.
        kParentPid,     // Parent process PID.
        kCommandLine,   // Startup parameters.
        kUser,          // User name.
        kStartTime,     // Startup time.
        kIsAdmin,       // Is administrator.
        kPplLevel,      // PPL protection level enumeration obtained via user-mode manual refresh.
        kProtection,    // R0: Protection status read
        kPpl,           // R0: Original PPL bytes read.
        kHandleCount,   // Process handle count.
        kHandleTable,   // Whether EPROCESS.ObjectTable is available.
        kSectionObject, // Whether EPROCESS.SectionObject is available.
        kR0Status,      // R0 extension field overall status.

        // ======== Columns aligned with the Windows
        // Task Manager 'Details' tab ======== Note:
        // - These columns are always appended after existing columns to preserve the logical index of old columns.
        // - All columns are hidden by default; enable them on demand via the "Select Columns" dialog or the header right-click menu.
        // - Display order can be adjusted by the user dragging the column header, independent of the enumeration order here.
        kPackageName,             // Package name (full UWP/MSIX package name).
        kStatus,                  // Status: Running / Suspended.
        kSessionId,               // Session ID.
        kJobObject,               // Job object ID (for ownership determination).
        kCpuTime,                 // CPU time (kernel mode + user mode cumulative).
        kCycleTime,               // Cycle (cumulative CPU cycles).
        kWorkingSet,              // Working set (memory).
        kPeakWorkingSet,          // Peak working set (memory).
        kWorkingSetDelta,         // Working set delta (memory).
        kActivePrivateWorkingSet, // Memory (active private working set).
        kPrivateWorkingSet,       // Memory (Private Working Set).
        kSharedWorkingSet,        // Memory (Shared Working Set).
        kCommitSize,              // Commit size.
        kPagedPool,               // Paged pool.
        kNonPagedPool,            // Non-paged pool.
        kPageFaults,              // Page fault.
        kPageFaultDelta,          // Page fault delta.
        kBasePriority,            // Base priority.
        kThreadCount,             // Thread count.
        kUserObjects,             // User objects.
        kGdiObjects,              // GDI objects.
        kIoReads,                 // I/O read count.
        kIoWrites,                // I/O write count.
        kIoOther,                 // I/O other count.
        kIoReadBytes,             // I/O read bytes.
        kIoWriteBytes,            // I/O write bytes.
        kIoOtherBytes,            // I/O other bytes.
        kOsContext,               // Operating system context (manifest supportedOS).
        kPlatform,                // Platform / Architecture.
        kUacVirtualization,       // UAC virtualization.
        kDescription,             // Description (Image Version Resource FileDescription).
        kDataExecutionPrevention, // Data Execution Prevention.
        kControlFlowGuard,        // Control flow protection.
        kHardwareStackProtection, // Hardware-enforced stack protection (CET shadow stack).
        kEnterpriseContext,       // Enterprise context.
        kDpiAwareness,            // DPI awareness.
        kPowerThrottling,         // Power throttling (efficiency mode).
        kGpuEngine,               // GPU engine.
        kGpuDedicatedMemory,      // Dedicated GPU memory.
        kGpuSharedMemory,         // Shared GPU memory.
        kProcessType,             // Type: application / background process / Windows process.
        kCpuCore,                 // CPU Core: Real logical processor per-core utilization fan chart.
        // Injection surface: only manually populated via the right-click 'Filter Injection Surface' option; does not follow periodic refresh.
        // It is a **count, not a conclusion**: among 310 processes opened in testing, 284 contained dynamic code. The binary
        // "has/has-not" distinction lacks discriminative power; what matters is the degree of outlier behavior in the count.
        kInjectionSurface,        // Injection surface: number of dynamic code regions / those that are writable and executable.
        kCount                    // Total columns.
    };

    // ProcessColumnGroup：
    // - Purpose: Group columns by semantics, used solely for display and retrieval in the "select columns" dialog.
    // - Does not affect the logical index of the column, nor participate in any data read/write paths.
    enum class ProcessColumnGroup : int
    {
        kGeneral = 0, // General: identity, path, user, and startup info.
        kPerformance, // Performance: real-time metrics for CPU, GPU, disk, network, etc.
        kMemory,      // Memory: Working set, committed, buffer pool, page faults.
        kIo,          // I/O: Read/write counts and byte counts.
        kSecurity,    // Security: signature, integrity, mitigation policies, virtualization.
        kKernel,      // Kernel: R0 extension field.
        kCount        // Total group count.
    };

    // ThreadTableColumn: Thread page table column index definitions.
    enum class ThreadTableColumn : int
    {
        kThreadId = 0,      // Thread ID.
        kOwnerPid,          // Associated process PID.
        kProcessName,       // Owning process name (with icon).
        kThreadClass,       // System threads / Ex worker thread classification.
        kStartAddress,      // Thread start address.
        kWin32StartAddress, // Win32StartAddress (R3 extended thread information).
        kTebBaseAddress,    // TEB base address (R3 extended thread information).
        kUserStackBase,     // User stack base (R3 extended thread information).
        kUserStackLimit,    // User stack limit (R3 extended thread information).
        kKernelStack,       // KTHREAD.KernelStack（R0 DynData）。
        kKStackBase,        // KTHREAD.StackBase（R0 DynData）。
        kKStackLimit,       // KTHREAD.StackLimit（R0 DynData）。
        kInitialStack,      // KTHREAD.InitialStack（R0 DynData）。
        kReadOps,           // KTHREAD ReadOperationCount。
        kWriteOps,          // KTHREAD WriteOperationCount。
        kOtherOps,          // KTHREAD OtherOperationCount。
        kReadBytes,         // KTHREAD ReadTransferCount。
        kWriteBytes,        // KTHREAD WriteTransferCount。
        kOtherBytes,        // KTHREAD OtherTransferCount。
        kThreadR0Status,    // R0 thread extension field status.
        kPriority,          // Dynamic priority.
        kBasePriority,      // Base priority.
        kThreadState,       // Thread state code (with text).
        kWaitReason,        // Wait reason code (with text).
        kKernelTimeMs,      // Kernel-mode cumulative time (milliseconds).
        kUserTimeMs,        // User-mode cumulative time (milliseconds).
        kCpuTimeMs,         // Cumulative CPU time (milliseconds).
        kWaitTimeTick,      // Wait duration counter.
        kContextSwitches,   // Context switch count.
        kCreateTime,        // Creation time.
        kProcessPath,       // Path of the owning process (may be empty).
        kCpuPercent,        // CPU single-core usage of adjacent snapshot threads (0~100).
        kCount              // Total columns.
    };

    // ThreadColumnLayout: Thread table A/B compact column presets; Custom indicates user manual adjustment.
    enum class ThreadColumnLayout : int
    {
        kPresetA = 0, // Scheduling overview: identity, priority, status, wait times, and CPU/switch statistics.
        kPresetB,     // Address diagnostics: identity, startup/TEB/kernel stack addresses, and R0 status.
        kCustom       // Custom layout after header menu interaction, dragging, or scaling.
    };

    // ThreadScopeFilter: Thread pages are classified and filtered by R3 System ownership and R0 ActiveExWorker status.
    enum class ThreadScopeFilter : int
    {
        kAll = 0,
        kSystem,
        kWorker
    };

    // ViewMode: Built-in view presets.
    // Notes:
    // - Each preset always includes the process name and PID to ensure the target is identifiable in any view;
    // - Presets only determine which columns are displayed by default; user adjustments in the 'Select Columns' dialog are applied on top of the presets.
    // - User-defined views are not part of this enum; they are maintained separately by m_customViews.
    enum class ViewMode : int
    {
        kMonitor = 0, // Monitoring: real-time counters for CPU, memory, disk, GPU, network, etc.
        kDetail,      // Detailed information: path, command line, user, signature, and other static and management data.
        kMemory,      // Memory analysis: Working set, committed memory, buffer pool, and page faults.
        kDiskIo,      // Disk I/O: read/write counts and byte counts.
        kGpu,         // GPU: utilization, engine, and video memory.
        kSecurity,    // Security and policies: signatures, elevation, virtualization, and various mitigation strategies.
        kKernel,      // Kernel evidence: R0 extended field.
        kCount        // Total number of built-in presets.
    };

    // ProcessCustomView：
    // - Purpose: Stores the name and visible column set of a user-defined view.
    // - Persisted in QSettings; retained across sessions.
    // - Ensure the process name and PID are always visible when applied.
    struct ProcessCustomView
    {
        QString name;                    // name: The user-input view name, which also serves as the configuration key.
        std::vector<int> visibleColumns; // visibleColumns: Logical indices of columns to be displayed in this view.
    };

    // ProcessTableRowKind：
    // - Process indicates a real process row, which can serve as the target for right-click, double-click, or R0/R3 operations;
    // - GroupHeader represents the 'App/Background Process/System' category title, responsible only for display and expansion.
    // - ApplicationAggregate represents the aggregated parent row for a specific application, displaying summary metrics and expanding actions to all member processes.
    enum class ProcessTableRowKind : int
    {
        kProcess = 0,
        kGroupHeader,
        kApplicationAggregate
    };

    // FriendlyProcessGroupType: Three-level classification for the friendly process view, ordered to match Task Manager/HUD.
    enum class FriendlyProcessGroupType : int
    {
        kApplication = 0,
        kBackground,
        kWindowsSystem
    };

    // DisplayRow: Data structure for the list rendering layer (with status flags).
    struct DisplayRow
    {
        ks::process::ProcessRecord* record = nullptr; // Points to the entity data in the cache.
        ProcessTableRowKind rowKind = ProcessTableRowKind::kProcess; // rowKind: real process / category header / application aggregation.
        FriendlyProcessGroupType friendlyGroupType = FriendlyProcessGroupType::kBackground; // friendlyGroupType: Friendly view category.
        QString syntheticTitle;                       // syntheticTitle: Display text for the synthetic row name column; empty for real processes.
        QString expansionKey;                         // expansionKey: Key for the expanded row state; real processes are typically empty.
        std::vector<std::string> actionIdentityKeys;   // actionIdentityKeys: All real process identifiers corresponding to the aggregated application rows.
        int depth = 0;                                // Indentation depth under the tree list.
        bool hasChildren = false;                     // hasChildren: whether child processes exist in the real tree or friendly view.
        bool isNew = false;                           // New processes in this round (highlighted in green).
        bool isExited = false;                        // Processes that exited this round but are retained for one round (gray highlighted).
        bool isKernelOnly = false;                    // Visible only to kernel enumeration (suspected hidden process, highlighted in red).
    };

    // ProcessTableRow：
    // - Purpose: Lightweight row object held by the QTableView model;
    // - Input source: rebuildTable generates based on DisplayRow and the maximum usage value of this round;
    // - Return behavior: this structure only carries data and does not actively return UI objects.
    struct ProcessTableRow
    {
        ks::process::ProcessRecord record;            // record: Process snapshot held by the table row to prevent dangling references after background refresh replaces the cache.
        std::string identityKey;                      // identityKey: PID + creation time, used for selection restoration and action binding.
        ProcessTableRowKind rowKind = ProcessTableRowKind::kProcess; // rowKind: Controls whether display and actions are allowed.
        FriendlyProcessGroupType friendlyGroupType = FriendlyProcessGroupType::kBackground; // friendlyGroupType: Category of the synthesized row.
        QString syntheticTitle;                       // syntheticTitle: Display title for categorized/aggregated rows.
        QString expansionKey;                         // expansionKey: Key for the expansion state of category/aggregation rows.
        std::vector<std::string> actionIdentityKeys;   // actionIdentityKeys: Member identifiers for aggregated batch actions in application rows.
        QList<std::uint32_t> cpuCoreProcessIds;         // cpuCoreProcessIds: Set of real PIDs participating in the summary, drawn per core.
        int depth = 0;                                // depth: The indentation level for tree display.
        bool hasChildren = false;                     // hasChildren: Used by the presentation layer to render tree expansion hints.
        bool isNew = false;                           // isNew: Highlight marker for new rows.
        bool isExited = false;                        // isExited: Highlight marker for the exited reserved line.
        bool isKernelOnly = false;                    // isKernelOnly: Flag to highlight processes visible only to the kernel.
        bool activitySnapshotActive = false;          // activitySnapshotActive: Indicates whether this line originates from a historical timeline snapshot.
    };

    using ProcessTableModel = ks::ui::FlatTableModel<ProcessTableRow>;

    // CacheEntry: Process cache entry (used to reuse static information and retain on exit).
    struct CacheEntry
    {
        ks::process::ProcessRecord record; // Complete process record.
        int missingRounds = 0;             // Consecutive missing rounds (1 indicates 'just exited, keep displayed').
        bool isNewInLatestRound = false;   // Whether it is a new entry in the latest refresh.
        bool isExitedInLatestRound = false;// Flag indicating if the process exited in the latest refresh cycle.
        bool isKernelOnlyInLatestRound = false; // Whether only kernel enumeration is visible in the latest refresh.
        std::uint32_t staticFillAttemptCount = 0; // Static detail fill attempt count (including success/failure).
        std::uint32_t staticFillFailureCount = 0; // Static detail consecutive failure count (used for backoff retry).
        // onDemandResolvedFlags：
        // - Static bits for ks::process::process_detail_demand that have already been successfully collected;
        // - Fields such as job ownership, mitigation policies, UAC virtualization, and image descriptions remain constant throughout the
        //   process lifecycle. Record them once to skip redundant queries in subsequent rounds, retaining only truly dynamic GUI resource counts.
        std::uint32_t onDemandResolvedFlags = 0;
    };

    // AffinityRestoreRetryState：
    // - Purpose: Record the backoff state after a process instance fails to restore persistent affinity.
    // - Invocation: restorePersistedAffinityForNewProcesses checks before the next refresh cycle;
    // - Return behavior: This structure only stores the consecutive failure count and the next allowed attempt time.
    struct AffinityRestoreRetryState
    {
        std::uint32_t consecutiveFailureCount = 0U; // consecutiveFailureCount: Count of consecutive recovery failures.
        std::chrono::steady_clock::time_point nextAttemptTime{}; // nextAttemptTime: The monotonic clock time when the next resume is allowed.
    };

    // ProcessActionTarget：
    // - Purpose: Saves a process snapshot bound to a right-click action;
    // - identityKey is used for cache write-back and maintaining selection; record is a read-only copy used during cross-thread execution.
    struct ProcessActionTarget
    {
        std::string identityKey;            // identityKey: Stable row identifier composed of PID and creation time.
        ks::process::ProcessRecord record;  // record: Copy of the process record used by the action execution thread.
        bool isKernelOnly = false;           // isKernelOnly: targets visible only in R0 cannot rely on Win32 handle validation.
    };

    // NetworkTrafficCounters：
    // - Input: network cumulative bytes per PID reported by the ETW collector;
    // - Processing: Accumulate RX/TX bytes by PID.
    // - Returns: a read-only snapshot for the refresh thread; rates are calculated via differential sampling from CounterSample.
    struct NetworkTrafficCounters
    {
        std::uint64_t rxBytes = 0; // rxBytes: Cumulative received bytes.
        std::uint64_t txBytes = 0; // txBytes: Cumulative uplink bytes.
    };

    // RefreshResult: Background thread refresh result object.
    struct RefreshResult
    {
        std::unordered_map<std::string, CacheEntry> nextCache;                    // Next round cache.
        std::unordered_map<std::string, ks::process::CounterSample> nextCounters; // Next round of counter samples.
        std::shared_ptr<const ks::process::CpuCoreUsageSnapshot> cpuCoreUsageSnapshot; // Background-constructed shared per-core snapshots; UI only moves the pointer.

        // ======== Statistical fields (used for UI status hints and detailed logging) ========
        std::size_t enumeratedCount = 0;        // Count of currently active processes enumerated in this round.
        std::size_t newProcessCount = 0;        // Number of new processes in this round.
        std::size_t exitedProcessCount = 0;     // Exited process count retained for this round (gray background retains one round).
        std::size_t reusedProcessCount = 0;     // Number of reused old cache entries in this round.
        std::size_t staticFilledCount = 0;      // Count of static details actually filled in this round.
        std::size_t staticDeferredCount = 0;    // Number of static details deferred this round due to budget or mode.
        std::size_t imagePathFilledCount = 0;   // Extra fill the count of imagePath for this round (used for icon display).
        std::uint64_t workerElapsedMs = 0;      // Elapsed time (ms) for this round of result construction by the background thread.
        int selectedStrategyIndex = 0;          // Index of the strategy selected by the UI (0/1).
        ks::process::ProcessEnumStrategy selectedStrategy{}; // Strategy enumeration mapped by index.
        ks::process::ProcessEnumStrategy actualStrategy{};   // Actual execution strategy (may fall back under Auto).
        bool detailModeEnabled = false;         // Whether the current round is in 'detailed view'.
        bool kernelCompareEnabled = false;      // Whether kernel process comparison is enabled in this round.
        bool kernelQuerySucceeded = false;      // Whether the kernel process query succeeded.
        std::size_t kernelEnumeratedCount = 0;  // Number of processes enumerated by the kernel.
        std::size_t kernelOnlyCount = 0;        // Count of processes visible only to the kernel (potentially hidden).
        std::string kernelQueryDetailText;      // Kernel query diagnostic text (errors or statistics).
    };

public:
    // ProcessActivityMetric: The process activity line chart supports switching displayed metrics.
    enum class ProcessActivityMetric : int
    {
        kCpu = 0,     // CPU percentage.
        kMemory,      // Memory working set in MB.
        kDisk,        // Disk throughput in MB/s.
        kNetwork,     // Network throughput KB/s.
        kGpu          // GPU percentage.
    };

    // ProcessActivityProcessPoint: Single-process historical snapshot within a single sampling point.
    //
    // Retain only fields that change during sampling and provide diagnostic value when reviewing resource usage; static
    // details like path, signature, and mitigation policies are not repeated for every sample point. All on-demand fields
    // are saved with their 'known' flag to prevent historical tables from misinterpreting uncollected values as 0.
    struct ProcessActivityProcessPoint
    {
        std::string identityKey;       // identityKey: PID + creation time, kept consistent with table selection.
        std::string processName;       // processName: Short name used for snapshot hover display.
        std::string imagePath;         // imagePath: The executable path at sampling time, used to restore the correct icon in the history table.
        std::string iconCacheKey;      // iconCacheKey: Stable icon cache key composed of process name and path.
        std::uint64_t creationTime100ns = 0; // creationTime100ns: Original process creation time, used to maintain identity in historical tables.
        std::uint32_t pid = 0;         // pid: Used for snapshot hover display and troubleshooting.
        double cpuPercent = 0.0;       // cpuPercent: CPU usage at the time of process sampling.
        double cpuCorePercent = 0.0;   // cpuCorePercent: Equivalent CPU usage for a single core of this process; may exceed 100%.
        double ramMB = 0.0;            // ramMB: Memory committed/submitted by the process at sampling time.
        double workingSetMB = 0.0;     // workingSetMB: actual working set at the time of process sampling.
        double diskMBps = 0.0;         // diskMBps: Disk throughput sampled for this process.
        double netKBps = 0.0;          // netKBps: Network throughput sampled for this process.
        double netRxKBps = 0.0;        // netRxKBps: The network download throughput of the process at the time of sampling.
        double netTxKBps = 0.0;        // netTxKBps: The network upload throughput of the process at the time of sampling.
        double gpuPercent = 0.0;       // gpuPercent: GPU percentage at the time of process sampling.

        // Scheduling, running status, and object usage.
        std::uint32_t threadCount = 0;          // threadCount: Number of threads during sampling.
        std::uint32_t handleCount = 0;          // handleCount: Number of handles at the time of sampling.
        std::uint32_t suspendedThreadCount = 0; // suspendedThreadCount: Number of threads suspended during sampling.
        std::int32_t basePriority = 0;          // basePriority: Base priority during sampling.
        bool processStateKnown = false;         // processStateKnown: Whether the running/suspended state was successfully determined.
        bool processSuspended = false;          // processSuspended: Whether all processes are suspended during sampling.
        bool efficiencyModeSupported = false;   // efficiencyModeSupported: indicates whether the efficiency mode status is available.
        bool efficiencyModeEnabled = false;     // efficiencyModeEnabled: Whether efficiency mode is enabled during sampling.

        // CPU and memory usage details.
        std::uint64_t rawCpuTime100ns = 0;               // rawCpuTime100ns: Cumulative CPU time.
        std::uint64_t cycleTime = 0;                     // cycleTime: Accumulated CPU cycle count.
        std::uint64_t rawWorkingSetBytes = 0;            // rawWorkingSetBytes: Exact working set size in bytes.
        std::uint64_t peakWorkingSetBytes = 0;           // peakWorkingSetBytes: Peak working set size.
        std::uint64_t privateWorkingSetBytes = 0;        // privateWorkingSetBytes: Private working set.
        std::uint64_t sharedWorkingSetBytes = 0;         // sharedWorkingSetBytes: Shared working set.
        std::uint64_t commitSizeBytes = 0;               // commitSizeBytes: Commit size.
        std::uint64_t pagedPoolBytes = 0;                // pagedPoolBytes: Paged pool usage.
        std::uint64_t nonPagedPoolBytes = 0;             // nonPagedPoolBytes: Non-paged pool usage.
        std::uint64_t pageFaultCount = 0;                // pageFaultCount: Cumulative page fault count.
        std::int64_t workingSetDeltaBytes = 0;           // workingSetDeltaBytes: Working set change between consecutive sampling rounds.
        std::int64_t pageFaultDeltaCount = 0;            // pageFaultDeltaCount: Change in page fault count between consecutive iterations.
        bool cycleTimeKnown = false;                     // cycleTimeKnown: Whether CPU cycle count is available.
        bool memoryDetailKnown = false;                  // memoryDetailKnown: Whether memory details are available.
        bool privateWorkingSetKnown = false;             // privateWorkingSetKnown: Indicates whether the private/shared working set is available.

        // I/O and GUI resource counts.
        std::uint64_t ioReadOperationCount = 0;          // ioReadOperationCount: Cumulative count of I/O read operations.
        std::uint64_t ioWriteOperationCount = 0;         // ioWriteOperationCount: Cumulative count of I/O write operations.
        std::uint64_t ioOtherOperationCount = 0;         // ioOtherOperationCount: Cumulative count of other I/O operations.
        std::uint64_t ioReadTransferBytes = 0;           // ioReadTransferBytes: cumulative number of bytes read.
        std::uint64_t ioWriteTransferBytes = 0;          // ioWriteTransferBytes: Cumulative bytes written.
        std::uint64_t ioOtherTransferBytes = 0;          // ioOtherTransferBytes: Cumulative count of bytes transferred via other I/O operations.
        std::uint32_t gdiObjectCount = 0;                // gdiObjectCount: GDI object count at the time of sampling.
        std::uint32_t userObjectCount = 0;               // userObjectCount: Number of USER objects at the time of sampling.
        bool ioDetailKnown = false;                      // ioDetailKnown: Whether I/O details are available.
        bool guiResourceKnown = false;                   // guiResourceKnown: Whether GUI resources have been collected.

        // GPU VRAM and currently occupied engine.
        std::uint64_t gpuDedicatedMemoryBytes = 0;       // gpuDedicatedMemoryBytes: Dedicated GPU memory usage.
        std::uint64_t gpuSharedMemoryBytes = 0;          // gpuSharedMemoryBytes: Shared GPU memory usage.
        std::string gpuEngineText;                       // gpuEngineText: GPU engine with the highest utilization during sampling.
        bool gpuMemoryKnown = false;                     // gpuMemoryKnown: Whether GPU memory count is available.
    };

    // ProcessActivitySample: A single activity sample from the process list.
    struct ProcessActivitySample
    {
        std::uint64_t sequence = 0;           // sequence: Monotonically increasing sequence number within the record.
        std::uint64_t elapsedMs = 0;          // elapsedMs: Milliseconds elapsed since the start of this recording.
        std::int64_t unixMilliseconds = 0;    // unixMilliseconds: Local timestamp, convenient for UI formatting.
        double totalCpuPercent = 0.0;         // totalCpuPercent: Global aggregated CPU usage.
        double totalMemoryMB = 0.0;           // totalMemoryMB: Global aggregated working set.
        double totalDiskMBps = 0.0;           // totalDiskMBps: Globally aggregated disk throughput.
        double totalNetKBps = 0.0;            // totalNetKBps: Global aggregated network throughput.
        double totalGpuPercent = 0.0;         // totalGpuPercent: Global aggregated GPU usage.
        std::vector<ProcessActivityProcessPoint> processes; // processes: Snapshot of processes still alive at this moment.
    };

private:
    // ======== UI initialization related ========
    void initializeUi();
    void initializeTopControls();
    void initializeProcessActivityPanel();
    void initializeProcessTable();
    void initializeCreateProcessPage();
    void initializeThreadPage();
    // initializeCrossViewPage:
    // - Create the R0 Cross-View evidence page for ProcessDock;
    // - Display the process/thread source matrix and exception flags on the page.
    // - Does not provide DKOM repair, process termination, or arbitrary write buttons.
    void initializeCrossViewPage();
    void initializeConnections();
    void initializeThreadPageConnections();
    // initializeCrossViewConnections:
    // - Connect Cross-View refresh, filtering, and table selection events.
    // - All R0 queries go through ArkDriverClient.
    // - Return value: None.
    void initializeCrossViewConnections();
    void initializeTimer();
    // applyAdaptiveColumnWidths:
    // - Set process table columns to interactive width mode;
    // - Request the global table column width adapter to compress default column widths according to the viewport.
    // - Does not return a value and does not modify horizontal/vertical scroll bar policies.
    void applyAdaptiveColumnWidths();
    int refreshIntervalMillisecondsFromInput() const;
    void applyRefreshIntervalInput();
    int tableRefreshIntervalMillisecondsFromInput() const;
    void applyTableRefreshIntervalInput();
    void initializeCreateProcessConnections();
    // showProcessSettingsDialog: Open the centralized settings window for the process list; the window reuses existing controls, and settings take effect immediately.
    void showProcessSettingsDialog();
    void focusProcessSearchBox(bool selectAllText);
    QString currentProcessSearchText() const;
    bool processRecordMatchesSearch(const ks::process::ProcessRecord& processRecord) const;

    // ======== Refresh and Rendering ========
    void requestAsyncRefresh(bool forceRefresh);
    void applyRefreshResult(RefreshResult refreshResult, bool forceUiRefresh);
    // restorePersistedAffinityForNewProcesses:
    // - Restore user-saved CPU affinity rules for process instances discovered in this round or those that failed to restore previously.
    // - Complete accounting upon success or explicit rule absence; on temporary failure, retry with capped exponential backoff.
    void restorePersistedAffinityForNewProcesses(RefreshResult& refreshResult);
    void rebuildTable();
    bool shouldRebuildProcessTableForRefresh(bool forceUiRefresh) const;
    void requestAsyncThreadRefresh(bool forceRefresh);
    void rebuildThreadTable();
    void applyThreadColumnLayout(ThreadColumnLayout layout);
    void clearThreadColumnPresetSelection();
    void updateThreadColumnPresetButtons();
    // refreshCrossViewAsync:
    // - Asynchronously query R0 process/thread cross-view evidence.
    // - Results are written back to m_processCrossViewCache / m_threadCrossViewCache;
    // - Return value: None.
    void refreshCrossViewAsync();
    // rebuildCrossViewTables:
    // - Redraw the PID/TID source matrix based on the current search box and cache;
    // - Perform UI projection only; do not query the driver again.
    // - Return value: None.
    void rebuildCrossViewTables();
    // showCrossViewDetailForCurrentRow:
    // - Display cross-view details for the currently selected process or thread.
    // - Parameter preferThreadTable: When true, prefer reading the thread table.
    // - Return value: None.
    void showCrossViewDetailForCurrentRow(bool preferThreadTable);
    std::vector<DisplayRow> buildDisplayOrder() const;
    std::vector<DisplayRow> buildTreeDisplayOrder() const;
    std::vector<DisplayRow> buildListDisplayOrder() const;
    std::vector<DisplayRow> buildFriendlyDisplayOrder() const;
    // buildFriendlyGroupTypeByPid:
    // - Calculate the 'App / Background Process / Windows Process' classification for each PID in any view mode.
    // - Ensures the 'Type' column aligned with Task Manager provides correct values in both tree and list views.
    // - Only invoked when the column is visible, avoiding window enumeration for hidden columns.
    // Returns: A mapping from PID to group type.
    std::unordered_map<std::uint32_t, FriendlyProcessGroupType> buildFriendlyGroupTypeByPid() const;
    std::vector<DisplayRow> buildActivitySnapshotDisplayOrder() const;
    void applyR0ColumnAvailability(const std::vector<DisplayRow>& displayRows);

    // ======== View Control ========
    void applyViewMode(ViewMode viewMode);
    void applyDefaultColumnWidths();
    bool isTreeModeEnabled() const;
    bool isFriendlyViewEnabled() const;
    ViewMode currentViewMode() const;

    // ======== View Presets and Custom Views ========
    // defaultVisibleColumnsForViewMode purpose:
    // - Returns the set of columns displayed by default for a specific built-in preset.
    // - Serves as the single source of truth shared by applyViewMode and 'restore defaults'.
    // Parameter viewMode: target preset.
    // Returns: The set of preset column logical indices (must include process name and PID).
    static std::vector<int> defaultVisibleColumnsForViewMode(ViewMode viewMode);

    // viewModeDisplayName: returns the display name for built-in presets in the dropdown.
    static QString viewModeDisplayName(ViewMode viewMode);

    // currentCustomViewIndex:
    // - Returns the index of the currently selected custom view;
    // - Returns -1 to indicate the currently selected item is a built-in preset.
    int currentCustomViewIndex() const;

    // applyCustomView:
    // - Apply a custom view's column set by index;
    // - Parameter customIndex: the index in m_customViews; ignored if out of bounds.
    void applyCustomView(int customIndex);

    // rebuildViewModeComboItems:
    // - Rebuild dropdown items based on built-in presets and the current custom view list.
    // - Block signals during rebuild to avoid triggering unnecessary view switches and refreshes.
    void rebuildViewModeComboItems();

    // saveCurrentColumnsAsCustomView:
    // - Save the currently visible columns as a named custom view; overwrite if the name already exists;
    // - Parameter viewName: the user-provided name (caller is responsible for trimming whitespace and null checks).
    // - Returns: the index of the saved view in m_customViews.
    int saveCurrentColumnsAsCustomView(const QString& viewName);

    // removeCustomView: Removes the custom view at the specified index and falls back to the monitoring view.
    void removeCustomView(int customIndex);

    // loadCustomViewsFromSettings / saveCustomViewsToSettings purpose:
    // - Read and write the user-defined view list in QSettings.
    void loadCustomViewsFromSettings();
    void saveCustomViewsToSettings() const;

    // isStaticDetailIntensiveViewActive:
    // - Check if the currently visible columns include static fields that require opening the process, such as Path, Command Line, User, Signature, or Description;
    // - Determines the static detail budget based on background refresh, avoiding hard-coding the budget judgment within the 'Detailed View'.
    // - Returns: true indicates that a higher static detail completion budget is required.
    bool isStaticDetailIntensiveViewActive() const;

    // ======== Table Interaction ========
    void showTableContextMenu(const QPoint& localPosition);
    void showThreadTableContextMenu(const QPoint& localPosition);
    void showThreadHeaderContextMenu(const QPoint& localPosition);
    void showHeaderContextMenu(const QPoint& localPosition);

    // ======== Process Table Column Management (Add/Remove
    // Columns) ======== showColumnChooserDialog purpose:
    // Opens the 'Select Columns' dialog to allow users to check which columns to display by group;
    // - Supports keyword search, select all, deselect all, and restore current view defaults.
    // - On confirmation, write user column overrides and apply immediately, while persisting to configuration.
    // Parameters: None.
    // Return value: None.
    void showColumnChooserDialog();

    // setProcessColumnVisible:
    // - Unified entry point for column visibility, responsible for writing user overrides, updating the table, and refreshing collection requirements;
    // - Parameter columnIndex: Target column logical index.
    // - Parameter visible: true to show, false to hide.
    // - Parameter persistImmediately: If true, write to configuration immediately; pass false during batch modifications to save all at the end.
    // - Return value: None.
    void setProcessColumnVisible(int columnIndex, bool visible, bool persistImmediately = true);

    // applyUserColumnVisibilityOverrides:
    // - After applying the base visibility from the view preset, restore the user's per-column selections on top.
    // - This ensures that switching between 'Monitor' and 'Detailed' views does not lose user-added columns.
    // - Return value: None.
    void applyUserColumnVisibilityOverrides();

    // resetProcessColumnsToViewDefault:
    // - Clear user column overrides and restore the process table to the default column set for the current view mode.
    // - Return value: None.
    void resetProcessColumnsToViewDefault();

    // loadProcessColumnLayoutFromSettings / saveProcessColumnLayoutToSettings: Purpose:
    // - Read and write user column visibility preferences in QSettings to persist configuration across sessions.
    // - Only save items that differ from the view defaults to avoid being locked to an old configuration after the default column set is adjusted.
    // - Return value: None.
    void loadProcessColumnLayoutFromSettings();
    void saveProcessColumnLayoutToSettings() const;

    // currentProcessDetailDemandFlags:
    // - Calculate the ks::process::process_detail_demand bitmap based on currently visible columns.
    // - Determines whether to incur additional collection costs for fields such as GDI, jobs, mitigation policies, or video memory based on background refresh settings.
    // - Returns: demand bitmap; returns None when no on-demand columns are visible.
    std::uint32_t currentProcessDetailDemandFlags() const;

    // isProcessColumnVisible:
    // - Check if a column is currently visible, reused for collection requirement calculations and dialog initialization.
    // - Parameter column: Target column.
    // - Returns true if the column is currently visible.
    bool isProcessColumnVisible(TableColumn column) const;

    // processColumnGroupOf / processColumnGroupTitle: Purpose:
    // - Provides grouping information required for the "Select Columns" dialog.
    // - Affects only dialog display, not data read/write operations.
    static ProcessColumnGroup processColumnGroupOf(TableColumn column);
    static QString processColumnGroupTitle(ProcessColumnGroup group);

    // processColumnDisplayName:
    // - Returns the header name for a column in the current language (excluding CPU/RAM summary suffixes);
    // - The list header text table is defined in an anonymous namespace in ProcessDock.cpp; this function is
    //   the sole entry point for other translation units (e.g., column selection dialogs) to access column names.
    // Parameter columnIndex: logical column index.
    // Returns: Column name; returns empty string if index out of bounds.
    static QString processColumnDisplayName(int columnIndex);
    void copyCurrentCell();
    void copyCurrentRow();
    void copyCurrentThreadCell();
    void copyCurrentThreadRow();
    void openProcessDetailsPlaceholder();
    // openSelectedProcessHotkeyScanner:
    // - Opens the current process detail window from the right-click context menu of the process list.
    // - Automatically switch to the 'Process Hotkey' page and start hotkey scanning;
    // - Supports only a single process to prevent multiple scan windows from being triggered by batch menu actions.
    void openSelectedProcessHotkeyScanner();
    // openSelectedProcessInjectionPage:
    // - Opens the current process detail window from the right-click context menu of the process list.
    // - Automatically switches to the 'Actions' tab, directly accessing the DLL/Shellcode injection area.
    // - Supports only a single process to prevent multiple detail windows from being triggered by batch menu actions.
    void openSelectedProcessInjectionPage();
    // showProcessDetailWindowForRecord:
    // - Reuse or create a process detail window based on the verified identity and record;
    // - Parameter identityKey: Stable key composed of PID + creation time;
    // - Input detailRecord: Process record for the detail window;
    // - Returns: Nothing.
    void showProcessDetailWindowForRecord(
        const std::string& identityKey,
        const ks::process::ProcessRecord& detailRecord);
    void openProcessDetailWindowByPid(std::uint32_t pid);
    void openThreadOwnerProcessDetails();
    // openThreadStackWindow:
    // - Open the Phase-8 call stack window for the selected row in the current thread list;
    // - R3 captures the user stack; the R0 field serves only as a kernel stack boundary for auxiliary diagnostics.
    void openThreadStackWindow();
    void executeSuspendThreadAction();
    void executeResumeThreadAction();
    void executeR0SuspendThreadAction();
      void executeR0ResumeThreadAction();
      void executeSuspendDriverThreadAction();
      void executeResumeDriverThreadAction();
      void executeTerminateDriverThreadAction(unsigned long terminateMethod);
      void executeExperimentalFirmwareRebootAction();
    void executeTerminateThreadAction();
    void executeR0TerminateThreadAction();
    void updateUsageSummaryInHeader(const std::vector<DisplayRow>& displayRows);

    // ======== Process activity recording and timeline ========
    bool isProcessActivityMetricEnabled(ProcessActivityMetric metric) const;
    bool isProcessActivityRefreshAllowedNow() const;
    bool isProcessActivityRecordingAllowedNow() const;
    bool isProcessListPageVisibleForRecording() const;
    template <typename Destination, typename Source>
    static void copyProcessActivityDynamicFields(Destination& destination, const Source& source);
    void appendProcessActivitySample();
    void synchronizeDetailWindowPerformanceHistory(
        ProcessDetailWindow* detailWindow,
        const std::string& identityKey) const;
    void appendProcessActivitySampleToDetailWindows(const ProcessActivitySample& sample);
    bool trimProcessActivitySamples();
    void refreshProcessActivityTimeline(bool indexShiftedLeft = false);
    void refreshProcessActivityChart();
    void updateProcessActivityStatusLabel();
    void previewProcessActivitySnapshotForIndex(int sampleIndex);
    void showProcessActivitySnapshotForIndex(int sampleIndex);
    void commitProcessActivityTimelineIndex(int sampleIndex);
    // handleProcessWindowPickerRelease:
    // - Receive release coordinates for the 'Process Tab Crosshair Drag Pick' action.
    // - Match the window under the mouse by window page logic and parse the associated PID;
    // - Set the process list filter to PID and open the details window for the corresponding process.
    // Parameter globalPos: Global screen coordinates at mouse release.
    // Return value: None. Report failures via a message box and logs.
    void handleProcessWindowPickerRelease(const QPoint& globalPos);
    bool isProcessActivityTableSnapshotActive() const;
    void rebuildProcessActivityTableSnapshotRecords();
    QString buildProcessActivitySnapshotText(int sampleIndex) const;
    std::vector<std::string> currentProcessActivitySelectionKeys() const;

    // ======== Process Control Actions ========
    // executeTerminateProcessAction function:
    // - Execute the 'Terminate Process Combo Action';
    // - Execute the R3 termination logic in a fixed order, and fall back to KswordARK R0 termination if the target does not exit after all R3 attempts.
    // - Use the same KLogEvent to chain the entire call chain logs and determine if the target process has truly terminated.
    void executeTerminateProcessAction();
    // executeTerminateAndDeleteImageAction:
    // - Only one target with a complete PID creation time and image path is allowed.
    // - Lock the same file object before termination; set the deletion status only after the original process exits.
    void executeTerminateAndDeleteImageAction();
    // executeTerminateProcessTreeAction:
    // - Identify the selected process and all its descendants solely based on the current R3 process snapshot;
    // - Each identified PID independently reuses the 'Terminate Process Tree' action.
    void executeTerminateProcessTreeAction();
    // executeR0TerminateProcessAction:
    // - Terminate the target process in kernel mode via R0 driver IOCTL requests;
    // - Success/failure details are uniformly written to the log panel.
    //
    // The 0dbbeaf1 commit on 2026-09-16 folded this into the R3 chain rollback, meaning "R0 only" can no longer
    // be initiated independently. If any of the 14 R3 methods succeeds, the R0 method is never executed.
    // When verifying a specific driver path in isolation, the read value is fake. Restore to an independent entry point as per the earlier implementation.
    // executeSingleTerminateMethodAction:
    // - Execute only the method at index methodIndex in the combination chain, once.
    // - Do not supplement the remaining methods or return to R0; doing so would result in an unclear outcome regarding who performed the action.
    void executeSingleTerminateMethodAction(std::size_t methodIndex);
    // openDmaProcessOpWindow:
    // - Open the DMA process operation window with the selected process as the target.
    void openDmaProcessOpWindow();
    void executeR0TerminateProcessAction();
    // executeR0TerminateProcessTreeAction:
    // - Identifies the selected process tree based only on the current R3 process snapshot.
    // - Submit existing terminate process IOCTLs individually for each PID in the tree.
    void executeR0TerminateProcessTreeAction();
    // executeR0SuspendProcessAction:
    // - Suspend the target process in kernel mode via R0 driver IOCTL requests;
    // - Success/failure details are uniformly written to the log panel.
    void executeR0SuspendProcessAction();
    // executeR0ResumeProcessAction:
    // - Restore suspended target processes via R0 driver IOCTL.
    // - Paired with executeR0SuspendProcessAction: if there is suspension without
    //   resumption, a target suspended via R0 can only exit that state by restarting.
    void executeR0ResumeProcessAction();
    // executeHvmProcessDispositionAction:
    // - Issue a single R-1 process disposition action (freeze / terminate / unblock);
    // - Freezing and terminating require a "guest linear address that will be executed", obtained from the dialog
    //   box and pre-filled with the main module entry point by default. The default value is only valid for newly
    //   started processes, so it is a mutable input rather than a fixed answer determined by the UI for the user;
    // Applies only to the first selected process: disposition is per-address-space. Batch execution would
    //   lose the mapping between 'which page corresponds to which process' within a single operation.
    void executeHvmProcessDispositionAction(unsigned long operation);
    // executeHvmInjectAction:
    // - Issue a single R-1 injection (load DLL / revoke).
    // - The trigger address is taken from the location the target thread is currently executing; the driver searches backward from that page for a gap.
    // - LoadLibraryW is resolved within this process: kernel32 has the same base address across the entire system for a single startup.
    void executeHvmInjectAction(unsigned long operation);
    // prepareHvmForArming:
    // - Complete the three prerequisites for R-1 installation in order (stop resident, release resources,
    //   CR3 tracking, prepare EPTP backend); return true on success, and report the cause on failure.
    // - Shared between disposal and injection. The order is strict; keeping two copies means one will inevitably be modified first.
    bool prepareHvmForArming(const QString& actionTitle, const KLogEvent& actionEvent);
    // stepFailedRestartResident:
    // - After installation, restore resident status. If this step fails, return true and report separately:
    //   the component is installed but no one is executing it; this is distinct from installation failure.
    bool stepFailedRestartResident(const QString& actionTitle, const KLogEvent& actionEvent);
    // hvmDispositionStatusAdvice:
    // - Translate the disposition status code into 'next steps' advice.
    // - Just displaying a number is meaningless: most of these codes indicate prerequisites are not met, and the
    //   actions required for each prerequisite differ, with two directions being opposite (not started vs. running).
    // - Returns an empty string if no advice is available; the caller displays the original line only.
    static QString hvmDispositionStatusAdvice(unsigned long status);
    // showHvmDispositionResult:
    // - Log the disposition result and display a popup to report it once.
    // - Pop-ups are mandatory: if prerequisites are not met, the action is rejected and only logged, leaving the UI completely silent.
    // - status is used to fetch the suggestion above; on failure, it is placed before the original row.
    // - successAdvice appears before the original line on success. Success means "the
    //   disposition was installed," not that the target has died or stopped—there is an
    //   uncertain time gap in between; without clarifying this period, it looks like a failure.
    void showHvmDispositionResult(
        const QString& title,
        bool actionOk,
        const std::string& detailText,
        unsigned long status,
        const KLogEvent& actionEvent,
        const QString& successAdvice = QString());
    // executeR0SetPplProtectionAction:
    // - Set target process PPL protection level via R0 driver IOCTL request;
    // - protectionLevel uses a single-byte native level encoding (Signer<<4 | Type).
    void executeR0SetPplProtectionAction(std::uint8_t protectionLevel, const QString& levelDisplayText);
    // executeR0SetProcessHiddenAction：
    // - Purpose: Modify or restore the visibility of the target process via R0; when hidden, visibilityFlags selects whether
    //   to modify only UniqueProcessId, only detach ActiveProcessLinks, or perform both operations for legacy compatibility.
    // - Parameter hidden: true hides the selected process; false unhides the selected process.
    // - Parameter visibilityFlags: Only effective when hidden=true; ignored during restoration and reverted according to driver records.
    void executeR0SetProcessHiddenAction(bool hidden, unsigned long visibilityFlags = 0UL);
    // executeR0ClearProcessHiddenAction：
    // - Purpose: Restore all processes modified by Ksword (PID/removed from chain) within the driver and refresh the process list.
    void executeR0ClearProcessHiddenAction();
    // executeR0SetBreakOnTerminationAction：
    // - Purpose: Set or clear the BreakOnTermination critical process flag via R0.
    // - Parameter enabled: true=enable; false=disable.
    void executeR0SetBreakOnTerminationAction(bool enabled);
    // executeR0DisableApcInsertionAction：
    // - Purpose: Clears the ApcQueueable bit of existing threads in the target process via R0.
    void executeR0DisableApcInsertionAction();
    // executeR0DkomRemoveFromCidTableAction：
    // - Purpose: Remove the target process's CID table entry from PspCidTable via R0.
    void executeR0DkomRemoveFromCidTableAction();
    // executeRefreshPplProtectionLevelAction:
    // - Manually refresh the enumeration of PPL protection levels for currently visible processes;
    // - Results are written only to the current UI snapshot and are not reused in the next cache cycle.
    // Invocation: triggered via process list right-click menu or manual refresh entry in detailed view.
    // Parameters: None.
    // Return value: None.
    // executeScreenInjectionSurfaceAction: Perform read-only injection surface filtering on the selected process;
    // fill only the 'Injection Surface' column. Do not follow periodic refreshes and do not generate conclusions.
    void executeScreenInjectionSurfaceAction();
    void executeRefreshPplProtectionLevelAction();
    // executeTerminateThreadsAction:
    // - Executes TerminateThread (all threads) separately (reserved for reuse by other entry points).
    // - Unlike the 'terminate process combined action', this function does not include the TerminateProcess step.
    void executeTerminateThreadsAction();
    void executeSuspendAction();
    void executeResumeAction();
    void executeSetCriticalAction(bool enableCritical);
    void executeSetPriorityAction(int priorityActionId);
    // executeSetProcessIntegrityAction:
    // - Input: integrityRid is the S-1-16-* Mandatory Label RID; levelDisplayText is the menu display text.
    // - Handling: Prefer R0 kernel API to write TokenIntegrityLevel; fall back to R3 if the driver is unavailable or outdated;
    // - Return: No return value; execution result is written to the unified action log.
    void executeSetProcessIntegrityAction(unsigned long integrityRid, const QString& levelDisplayText);
    // executeSetEfficiencyModeAction: Enable/disable Windows process efficiency mode.
    void executeSetEfficiencyModeAction(bool enableEfficiencyMode);
    void executeOpenFolderAction();
    // executeOpenMemoryOperationAction purpose: Jumps to the memory page and attaches the current process to facilitate further dumping or viewing of the region.
    void executeOpenMemoryOperationAction();
    void executeFocusHandleAction();
    void executeFocusNetworkAction();
    void executeFocusWindowAction();
    // executeOpenMessageHooksAction: Opens a non-modal window to display message hooks applied to the target process thread.
    void executeOpenMessageHooksAction(const ks::process::ProcessRecord& targetRecord);

    // ======== Utility Functions ========
    std::string selectedIdentityKey() const;
    ks::process::ProcessRecord* selectedRecord();
    std::vector<ProcessActionTarget> selectedActionTargets() const;
    std::vector<ProcessActionTarget> processTreeActionTargets() const;
    void clearProcessTableSelection();
    void syncTrackedSelectionFromTable();
    // processNumericSortValue:
    // - Provide a unique raw numeric sort key for the standard list delegate and the friendly view.
    // - When adding a new numeric column with units, register it here only to avoid drift between two sets of column comparators.
    // Return: Valid QVariant for numeric columns; invalid QVariant for sorting by display text.
    static QVariant processNumericSortValue(
        const ks::process::ProcessRecord& processRecord,
        TableColumn column);
    // processUsageHighlightValue: Returns a non-negative magnitude requiring intensity coloring; returns false if not collected or if the column is not an indicator.
    static bool processUsageHighlightValue(
        const ks::process::ProcessRecord& processRecord,
        TableColumn column,
        double* valueOut);
    // processUsageHighlightRatio: Normalizes cell values to 0~1 based on the current column's maximum.
    bool processUsageHighlightRatio(
        const ks::process::ProcessRecord& processRecord,
        TableColumn column,
        double* ratioOut) const;
    QVariant processTableData(const ProcessTableRow& tableRow, int column, int role);
    const ProcessTableRow* processTableRowForViewIndex(const QModelIndex& viewIndex) const;
    QModelIndex processTableViewIndexForIdentityKey(const std::string& identityKey, int column) const;
    std::vector<QModelIndex> selectedProcessTableRowIndexes(bool includeCurrentFallback) const;
    ProcessActionTarget processActionTargetFromTableRow(const ProcessTableRow& tableRow) const;
    void appendProcessActionTargetsFromTableRow(
        const ProcessTableRow& tableRow,
        std::vector<ProcessActionTarget>& actionTargets,
        std::unordered_set<std::string>& visitedIdentitySet) const;
    void dispatchProcessActionTargetsInParallel(
        const QString& actionTitle,
        const std::vector<ProcessActionTarget>& actionTargets,
        const std::function<bool(const ProcessActionTarget&, std::string*)>& actionInvoker,
        bool refreshWhenAnySucceeded,
        bool forceAsyncWithTimeout = false,
        bool requireVerifiedProcessIdentity = false);
    // executeTerminateProcessActions：
    // - When includeR0Fallback is true, if none of the 14 R3 methods cause the target to exit, a fallback R0 attempt is made.
    //   When false, only the R3 portion runs; R0 is not involved at all.
    // - Passing false for "Terminate Process (R3)" in the menu: it promises to use only
    //   R3, so naming an action that calls a driver behind the scenes as such is misleading.
    void executeTerminateProcessActions(
        const QString& actionTitle,
        const std::vector<ProcessActionTarget>& actionTargets,
        bool deleteImageAfterExit = false,
        bool includeR0Fallback = true);
    void executeR0TerminateProcessActions(
        const QString& actionTitle,
        const std::vector<ProcessActionTarget>& actionTargets);
    const ks::process::SystemThreadRecord* selectedThreadRecord() const;
    void bindContextActionToIndex(const QModelIndex& clickedIndex);
    void clearContextActionBinding();
    void bindThreadContextActionToItem(QTreeWidgetItem* clickedItem);
    void clearThreadContextActionBinding();
    bool threadRecordMatchesSearch(const ks::process::SystemThreadRecord& threadRecord) const;
    bool threadRecordMatchesScope(const ks::process::SystemThreadRecord& threadRecord) const;
    QString formatColumnText(const ks::process::ProcessRecord& processRecord, TableColumn column, int depth) const;
    QString formatThreadColumnText(const ks::process::SystemThreadRecord& threadRecord, ThreadTableColumn column) const;
    QString threadStateText(std::uint32_t stateValue) const;
    QString threadWaitReasonText(std::uint32_t waitReasonValue) const;
    QIcon resolveProcessIcon(const ks::process::ProcessRecord& processRecord);
    void queueProcessIconExtractionsForCurrentProcesses();
    void queueProcessIconExtraction(const QString& imagePath);
    void applyProcessIconExtractionResult(
        const QString& imagePath,
        QImage iconImage,
        std::uint64_t extractionGeneration);
    void refreshProcessTableRowsForIcon(const QString& imagePath);
    QIcon blueTintedIcon(const char* iconPath, const QSize& iconSize = QSize(16, 16)) const;
    // tintedProcessTabIcon: Redraws the process tab icon with a specified color to avoid blue-on-blue appearance in the selected state.
    QIcon tintedProcessTabIcon(const char* iconPath, const QColor& tintColor, const QSize& iconSize = QSize(16, 16)) const;
    // refreshSideTabIconContrast: Refreshes the color of the selected top tab icon to improve page visibility.
    void refreshSideTabIconContrast();
    QString buildThreadContextMenuStyle() const;
    // showActionResultMessage purpose: uniformly log process action results (without pop-ups) and reuse the same KLogEvent to maintain call chain continuity.
    // Create a KLogEvent in the action function, then pass the same event object to this function.
    // Parameters: title - action title; actionOk - whether the action succeeded; detailText - action details; actionEvent - the full-link event object for this action.
    // Return value: None.
    void showActionResultMessage(const QString& title, bool actionOk, const std::string& detailText, const KLogEvent& actionEvent);
    QObject* mainWindowActionReceiver() const;
    bool invokeMainWindowPidSlot(const char* methodName, std::uint32_t pid) const;
    bool invokeMainWindowPidListSlot(const char* methodName, const QString& pidListText) const;
    void connectDetailWindowNavigation(ProcessDetailWindow* detailWindow);
    ks::process::CreateProcessRequest buildCreateProcessRequestFromUi(bool* buildOk, QString* errorTextOut) const;
    // buildTokenPrivilegeEditRequestFromUi:
    // - Only read the Token mode and privilege table fields, without parsing other CreateProcessW inputs;
    // - Used for the 'Apply Token Adjustments Only' button to prevent unrelated creation parameters from blocking privilege adjustment operations;
    // - Return value: true indicates requestOut is populated with Token-related fields; false indicates errorTextOut contains the failure reason.
    bool buildTokenPrivilegeEditRequestFromUi(ks::process::CreateProcessRequest* requestOut, QString* errorTextOut) const;
    void executeCreateProcessRequest();
    void executeApplyTokenPrivilegeEditsOnly();
    void appendCreateResultLine(const QString& lineText);
    void browseCreateProcessApplicationPath();
    void browseCreateProcessCurrentDirectory();
    void resetCreateProcessForm();
    void bindBitmaskEditor(QLineEdit* valueEdit, std::vector<QCheckBox*>* checkBoxList, const QString& fieldDisplayName);
    void syncEditValueFromBitmaskChecks(QLineEdit* valueEdit, const std::vector<QCheckBox*>* checkBoxList);
    void syncBitmaskChecksFromEditValue(QLineEdit* valueEdit, const std::vector<QCheckBox*>* checkBoxList, const QString& fieldDisplayName);
    static std::string buildRulerPrefix(int depth);
    static int toColumnIndex(TableColumn column);
    static int toThreadColumnIndex(ThreadTableColumn column);
    static bool parseUnsignedText(const QString& text, std::uint64_t& valueOut);
    static std::uint32_t parseUInt32WithDefault(const QString& text, std::uint32_t defaultValue, bool* parseOkOut = nullptr);
    static std::uint64_t parseUInt64WithDefault(const QString& text, std::uint64_t defaultValue, bool* parseOkOut = nullptr);
    static QSet<std::uint32_t> collectVisibleWindowPidSet();
    static std::uint32_t findFriendlyApplicationRootPid(
        std::uint32_t pid,
        const std::unordered_map<std::uint32_t, std::uint32_t>& parentPidByPid,
        const QSet<std::uint32_t>& visibleWindowPidSet);
    static bool isFriendlyWindowsSystemProcess(
        const ks::process::ProcessRecord& processRecord,
        const QString& normalizedWindowsDirectoryPath);
    static QString friendlyGroupTitle(FriendlyProcessGroupType groupType, int entryCount);
    // friendlyGroupTypeName:
    // - Returns the short group name without member counts for the 'Type' column in Task Manager, displayed line by line.
    // - Parameter groupType: Friendly group to which the row belongs;
    // - Return: Text for application / background process / Windows process.
    static QString friendlyGroupTypeName(FriendlyProcessGroupType groupType);
    static QString friendlyExpansionKeyForGroup(FriendlyProcessGroupType groupType);
    static QString friendlyExpansionKeyForApplication(std::uint32_t rootPid);
    static ks::process::ProcessRecord aggregateFriendlyApplicationRecord(
        const std::vector<const CacheEntry*>& applicationEntries,
        std::uint32_t rootPid);

    // ======== Background Thread Core Functions (Static) ========
    static RefreshResult buildRefreshResult(
        int strategyIndex,
        bool detailModeEnabled,
        bool queryKernelProcessList,
        int staticDetailFillBudget,
        std::uint32_t detailDemandFlags,
        std::uint64_t refreshTicket,
        const std::unordered_map<std::string, CacheEntry>& previousCache,
        const std::unordered_map<std::string, ks::process::CounterSample>& previousCounters,
        const std::unordered_map<std::uint32_t, NetworkTrafficCounters>& networkTrafficSnapshot,
        std::uint32_t logicalCpuCount);

    // ======== Process network throughput sampling ========
    void ensureProcessNetworkTrafficCaptureStarted();
    void stopProcessNetworkTrafficCapture();
    void pruneProcessNetworkTrafficCounters();
    std::unordered_map<std::uint32_t, NetworkTrafficCounters> snapshotProcessNetworkTrafficCounters() const;

    // ======== Per-core CPU sampling for processes/threads ========
    void ensureCpuCoreUsageCaptureStarted();
    void stopCpuCoreUsageCapture();
    void syncCpuCoreUsageToDetailWindow(
        ProcessDetailWindow* detailWindow,
        const ks::process::ProcessRecord& processRecord) const;

private:
    QPointer<QObject> mainWindowActionReceiver_; // mainWindow receiver at construction time to prevent parent() from becoming the Dock container after ADS remounting.

    // ======== Top-Level Layout ========
    QVBoxLayout* rootLayout_ = nullptr;      // Root layout: contains only the top Tab.
    QTabWidget* sideTabWidget_ = nullptr;    // Top tab bar (North), containing four process function pages.
    QWidget* processListPage_ = nullptr;     // "Process List" page container.
    QVBoxLayout* processPageLayout_ = nullptr; // Process page main layout.
    QWidget* createProcessPage_ = nullptr;   // "Create Process" page container.
    QVBoxLayout* createProcessPageLayout_ = nullptr; // Create the main page layout.
    QWidget* threadPage_ = nullptr;          // "Thread List" page container.
    QVBoxLayout* threadPageLayout_ = nullptr; // Thread page main layout.
    QWidget* crossViewPage_ = nullptr;       // Container for the "Cross-View" page.
    QVBoxLayout* crossViewPageLayout_ = nullptr; // Cross-View page main layout.

    // ======== Control Bar ========
    QHBoxLayout* controlLayout_ = nullptr;   // Layout for the 'Action Buttons' row above.
    QComboBox* strategyCombo_ = nullptr;     // Process traversal strategy combo box.
    QDialog* processSettingsDialog_ = nullptr; // Process list settings window; non-modal, reusing existing settings controls.
    QVBoxLayout* processSettingsLayout_ = nullptr; // Set the window to a single-column layout.
    QComboBox* viewModeCombo_ = nullptr;     // Monitor view / Details view combo box.
    QPushButton* startButton_ = nullptr;     // Start monitoring button.
    QPushButton* pauseButton_ = nullptr;     // Pause monitoring button.
    QCheckBox* friendlyViewCheck_ = nullptr; // Process friendly view: categorize apps/background processes/system processes; enabled by default.
    QCheckBox* kernelCompareCheck_ = nullptr;// Whether to additionally request the kernel process list and perform a diff comparison during refresh.
    QCheckBox* showKswordHiddenProcessCheck_ = nullptr; // Whether to show processes hidden from the chain by Ksword R0.
    QLineEdit* processSearchLineEdit_ = nullptr; // Process search box: filters the current list by keywords such as name, PID, or path.
    QLabel* refreshLabel_ = nullptr;         // List refresh interval label.
    QDoubleSpinBox* tableRefreshIntervalSpin_ = nullptr; // Process table refresh interval spin box, range 0.5~60 seconds, default 2 seconds.
    QLabel* sampleIntervalLabel_ = nullptr;  // Active sampling interval label.
    QDoubleSpinBox* refreshIntervalSpin_ = nullptr; // Activity sampling / background monitoring interval step box, 0.05~60 seconds, default 1 second.
    QPushButton* columnChooserButton_ = nullptr; // "Choose Columns" button: opens the dialog to add/remove columns.
    QPushButton* processSettingsButton_ = nullptr; // Gear button: Opens the process list settings window.

    // ======== Process activity log panel ========
    QWidget* activityPanelWidget_ = nullptr;       // m_activityPanelWidget: Process activity graph panel.
    ProcessActivityChartWidget* activityChartWidget_ = nullptr; // m_activityChartWidget: Line chart showing time-axis percentages.
    ProcessActivityTimelineSlider* activityTimelineSlider_ = nullptr; // m_activityTimelineSlider: Hides the internal timeline; interaction is handled via line chart clicks.
    QPushButton* activityClearButton_ = nullptr;   // m_activityClearButton: Clears the current refresh record cache.
    QCheckBox* activityBackgroundRecordCheck_ = nullptr; // Background refresh/recording toggle switch
    QCheckBox* activityListOnlyRefreshCheck_ = nullptr; // Switch to refresh only the process list, without writing activity records.
    QPushButton* activityCpuButton_ = nullptr;     // CPU metrics display button.
    QPushButton* activityMemoryButton_ = nullptr;  // Memory metrics display button.
    QPushButton* activityDiskButton_ = nullptr;    // Disk metrics display button.
    QPushButton* activityNetworkButton_ = nullptr; // Network metrics display button.
    QPushButton* activityGpuButton_ = nullptr;     // GPU metrics display button.
    QPushButton* activityProcessPickerButton_ = nullptr; // Crosshair drag button: Filter processes by target window PID and open process details.
    QLabel* activitySnapshotLabel_ = nullptr;      // Time axis hover snapshot summary.
    bool activityRecordingEnabled_ = false;        // m_activityRecordingEnabled: derived from refresh status; refresh triggers recording.
    bool activityTimelinePinnedToLatest_ = true;   // Automatically pin the timeline to the latest when it is at the far right.
    bool activityTimelineSliderUpdating_ = false;  // Suppress user-mode checks when the program updates the slider.
    int activityTableSnapshotIndex_ = -1;           // The historical sample currently bound to the process table below; -1 indicates the real-time list.
    std::uint64_t activityNextSequence_ = 0;       // Record sample sequence number.
    std::uint64_t activityRecordingStartTick100ns_ = 0; // Steady tick when this recording started.
    double activityTotalPhysicalMemoryMB_ = 0.0;    // Total physical memory, used to convert memory metrics to percentages.
    std::deque<ProcessActivitySample> activitySamples_; // Bounded double-ended record cache; evicting old samples does not shift the entire sequence.
    std::vector<ks::process::ProcessRecord> activityTableSnapshotRecords_; // Process table records mapped from historical samples.

    // ======== Process Table ========
    QTableView* processTable_ = nullptr;     // Process list table view (supports column drag/sort/right-click).
    QDialog* dmaProcessOpDialog_ = nullptr;  // DMA process operation window (created on demand, reused).
    ksword::memory_dock::DmaProcessOpPage* dmaProcessOpPage_ = nullptr; // Page body within the window.
    ProcessTableModel* processTableModel_ = nullptr; // Lightweight process list model to avoid rebuilding items during refresh.
    QSortFilterProxyModel* processSortProxy_ = nullptr; // Process list sort proxy, preserving numeric column sort behavior.
    std::array<double, static_cast<std::size_t>(TableColumn::kCount)> processUsageHighlightMaximums_{}; // Maximum intensity thresholds for each usage metric column in the current process table.
    QHash<int, bool> userColumnVisibilityOverride_; // User-specific column visibility toggles; the key is the logical column index, and the default indicates following the view's default.
    std::vector<ProcessCustomView> customViews_;    // User-defined view list, persisted in QSettings.
    bool viewModeComboUpdating_ = false;            // Suppress user switch handling while the program rebuilds the dropdown items.
    std::uint32_t lastProcessDetailDemandFlags_ = 0; // Bitmap of on-demand collection flags for the most recent background refresh request, used to trigger an immediate refresh upon changes.
    QHash<QString, bool> friendlyExpandedStateByKey_; // Friendly view category/application aggregation row expansion state; defaults to expanded.
    int friendlySortColumn_ = static_cast<int>(TableColumn::kName); // Friendly view internal sort column, defaulting to process name A-Z.
    Qt::SortOrder friendlySortOrder_ = Qt::AscendingOrder; // Sort direction within the friendly view; toggled by clicking the column header.
    bool friendlySortActive_ = false; // Whether the header has been clicked for sorting; the first click on any column defaults to ascending order.
    bool flatListForcedByHeaderSort_ = false; // After clicking the tree view header, it enters a standard flat enumeration without changing the friendly view checkbox.
    mutable std::vector<ks::process::ProcessRecord> friendlySyntheticRecords_; // Friendly view synthetic title / aggregated row record cache.

    // ======== Thread Page Controls ========
    QHBoxLayout* threadTopLayout_ = nullptr; // Thread page top action bar.
    QPushButton* threadRefreshButton_ = nullptr; // Thread page refresh button (icon button).
    QWidget* threadColumnPresetWidget_ = nullptr; // Adjacent button container for A/B compact presets.
    QHBoxLayout* threadColumnPresetLayout_ = nullptr; // Layout for preset buttons with zero spacing.
    QPushButton* threadColumnPresetAButton_ = nullptr; // A: Scheduling overview column.
    QPushButton* threadColumnPresetBButton_ = nullptr; // B: Address/Diagnostic column.
    QComboBox* threadScopeCombo_ = nullptr; // Filtering by All / System / ActiveExWorker categories.
    QLineEdit* threadSearchLineEdit_ = nullptr; // Thread page search box (filter by TID/PID/name).
    QTreeWidget* threadTable_ = nullptr;     // Thread list table (supports right-click actions).
    ThreadColumnLayout threadColumnLayout_ = ThreadColumnLayout::kPresetA; // Current highlight preset (default: A).
    bool threadApplyingColumnLayout_ = false; // Blocks header manual change signals when the program applies the preset.

    // ======== Cross-View Page Control ========
    QHBoxLayout* crossViewTopLayout_ = nullptr; // Cross-View top toolbar.
    QPushButton* crossViewRefreshButton_ = nullptr; // Cross-View refresh button.
    QLineEdit* crossViewSearchEdit_ = nullptr; // Cross-View full-field filter box.
    QCheckBox* crossViewAnomalyOnlyCheck_ = nullptr; // Show anomaly records only.
    QLabel* crossViewStatusLabel_ = nullptr; // Cross-View query status.
    QTableWidget* processCrossViewTable_ = nullptr; // Process source matrix table.
    QTableWidget* threadCrossViewTable_ = nullptr; // Thread source matrix table.
    CodeEditorWidget* crossViewDetailEdit_ = nullptr; // Cross-View detail text editor, read-only.

    // ======== Creating Process Page - Common Parameters ========
    QComboBox* createMethodCombo_ = nullptr; // CreateProcessW / Token path.
    QLineEdit* applicationNameEdit_ = nullptr;
    QPushButton* applicationBrowseButton_ = nullptr;
    QCheckBox* useApplicationNameCheck_ = nullptr;
    QLineEdit* commandLineEdit_ = nullptr;
    QCheckBox* useCommandLineCheck_ = nullptr;
    QLineEdit* currentDirectoryEdit_ = nullptr;
    QPushButton* currentDirectoryBrowseButton_ = nullptr;
    QCheckBox* useCurrentDirectoryCheck_ = nullptr;
    QPlainTextEdit* environmentEditor_ = nullptr;
    QCheckBox* useEnvironmentCheck_ = nullptr;
    QCheckBox* environmentUnicodeCheck_ = nullptr;
    QCheckBox* inheritHandleCheck_ = nullptr;
    QLineEdit* creationFlagsEdit_ = nullptr;
    std::vector<QCheckBox*> creationFlagChecks_; // dwCreationFlags: Checked set of creation flags.

    // ======== Create Process Page - SECURITY_ATTRIBUTES ========
    QCheckBox* useProcessSecurityCheck_ = nullptr;
    QLineEdit* processSecurityLengthEdit_ = nullptr;
    QLineEdit* processSecurityDescriptorEdit_ = nullptr;
    QCheckBox* processSecurityInheritCheck_ = nullptr;
    QCheckBox* useThreadSecurityCheck_ = nullptr;
    QLineEdit* threadSecurityLengthEdit_ = nullptr;
    QLineEdit* threadSecurityDescriptorEdit_ = nullptr;
    QCheckBox* threadSecurityInheritCheck_ = nullptr;

    // ======== Create Process Page - STARTUPINFOW ========
    QCheckBox* useStartupInfoCheck_ = nullptr;
    QLineEdit* siCbEdit_ = nullptr;
    QLineEdit* siReservedEdit_ = nullptr;
    QLineEdit* siDesktopEdit_ = nullptr;
    QLineEdit* siTitleEdit_ = nullptr;
    QLineEdit* siXEdit_ = nullptr;
    QLineEdit* siYEdit_ = nullptr;
    QLineEdit* siXSizeEdit_ = nullptr;
    QLineEdit* siYSizeEdit_ = nullptr;
    QLineEdit* siXCountCharsEdit_ = nullptr;
    QLineEdit* siYCountCharsEdit_ = nullptr;
    QLineEdit* siFillAttributeEdit_ = nullptr;
    QLineEdit* siFlagsEdit_ = nullptr;
    std::vector<QCheckBox*> startupFillAttributeChecks_; // Set of checkboxes for STARTUPINFO.dwFillAttribute.
    std::vector<QCheckBox*> startupFlagChecks_; // STARTUPINFO.dwFlags check set.
    QLineEdit* siShowWindowEdit_ = nullptr;
    QLineEdit* siCbReserved2Edit_ = nullptr;
    QLineEdit* siReserved2PtrEdit_ = nullptr;
    QLineEdit* siStdInputEdit_ = nullptr;
    QLineEdit* siStdOutputEdit_ = nullptr;
    QLineEdit* siStdErrorEdit_ = nullptr;

    // ======== Create Process Page - PROCESS_INFORMATION ========
    QCheckBox* useProcessInfoCheck_ = nullptr;
    QLineEdit* piProcessHandleEdit_ = nullptr;
    QLineEdit* piThreadHandleEdit_ = nullptr;
    QLineEdit* piPidEdit_ = nullptr;
    QLineEdit* piTidEdit_ = nullptr;

    // ======== Process Creation Page - Token Path ========
    QLineEdit* tokenSourcePidEdit_ = nullptr;
    QLineEdit* tokenDesiredAccessEdit_ = nullptr;
    QCheckBox* tokenDuplicatePrimaryCheck_ = nullptr;
    std::vector<QCheckBox*> tokenDesiredAccessChecks_; // Token DesiredAccess check set.
    QTableWidget* tokenPrivilegeTable_ = nullptr;
    QPushButton* applyTokenPrivilegeButton_ = nullptr;
    QPushButton* resetTokenPrivilegeButton_ = nullptr;

    // ======== Process Creation Page - Actions and Output ========
    QPushButton* launchProcessButton_ = nullptr;
    QPushButton* resetCreateFormButton_ = nullptr;
    QTextEdit* createResultOutput_ = nullptr;

    // ======== Refresh Scheduling ========
    QTimer* refreshTimer_ = nullptr;         // Periodic refresh timer.
    bool monitoringEnabled_ = true;          // Whether currently in monitoring state.
    bool refreshInProgress_ = false;         // Mutex flag to prevent concurrent refresh.
    bool autoHideUnavailableR0Columns_ = false; // Automatically hide kernel-exclusive columns when the R0 extension round is unavailable.
    std::uint64_t refreshTicket_ = 0;        // Refresh request sequence number (to prevent out-of-order processing).
    std::uint32_t logicalCpuCount_ = 1;      // Number of CPU cores (conversion from CPU percentage).
    std::chrono::steady_clock::time_point lastRefreshStartTime_{}; // The refresh start time recorded by the main thread.
    std::chrono::steady_clock::time_point lastCpuCoreUsageSnapshotTime_{}; // timestamp of the last per-core matrix settlement submission, independently limited to at least 1 second.
    std::chrono::steady_clock::time_point lastProcessTableRebuildTime_{}; // Time of the last process table redraw.

    // ======== Data Cache ========
    std::unordered_map<std::string, CacheEntry> cacheByIdentity_; // Process cache (PID + CreateTime).
    std::unordered_set<std::string> affinityRestoreCompletedIdentityKeys_; // Process instances that have been successfully restored or have no rules.
    std::unordered_map<std::string, AffinityRestoreRetryState> affinityRestoreRetryByIdentity_; // Process instances that temporarily failed and are waiting for retry.
    std::unordered_map<std::string, ks::process::CounterSample> counterSampleByIdentity_; // Delta sample.
    std::unique_ptr<ks::network::ProcessNetworkEtwMonitor> processNetworkTrafficService_; // ETW network accumulator within the process page.
    bool processNetworkTrafficCaptureStarted_ = false; // Whether the ETW collector has attempted to start.
    std::shared_ptr<ks::process::ProcessCpuCoreEtwMonitor> cpuCoreUsageService_; // A single system-level CSwitch session; background snapshot tasks share the same lifecycle.
    bool cpuCoreUsageCaptureStarted_ = false; // UI thread status: Whether the start has been dispatched in this monitoring cycle.
    bool cpuCoreUsageStopInProgress_ = false; // UI thread state: prohibit a second session before the asynchronous Stop/join completes.
    std::shared_ptr<std::atomic_bool> cpuCoreUsageCaptureDesired_ =
        std::make_shared<std::atomic_bool>(false); // The expected state read after the background Start returns, resolving the fast start/pause race condition.
    std::shared_ptr<const ks::process::CpuCoreUsageSnapshot> latestCpuCoreUsageSnapshot_; // Most recent interval snapshot; the UI only swaps shared pointers to avoid copying the full matrix.
    QHash<QString, QIcon> iconCacheByPath_;  // Process icon cache to avoid repeated extraction.
    QHash<QString, QIcon> activityIconCacheByProcessKey_; // Historical activity icon cache: process name + path -> icon.
    QSet<QString> processIconPathsInFlight_; // Set of EXE paths submitted to the background thread pool awaiting results.
    std::uint64_t processIconExtractionGeneration_ = 0; // Icon task generation; invalidates results from older tasks after a pause.
    QThreadPool processIconExtractionPool_; // Dedicated icon thread pool to prevent numerous Shell queries from saturating the general background task pool.
    std::unordered_map<std::string, QPointer<ProcessDetailWindow>> detailWindowByIdentity_; // Detail window cache (reuse window for the same process).
    std::unordered_map<std::string, std::chrono::steady_clock::time_point> detailWindowLastSyncTimeByIdentity_; // timestamp of the last sync for the detail window, to avoid triggering heavy parsing on every refresh.
    std::string trackedSelectedIdentityKey_; // The currently selected process identityKey; used to restore highlighting after the table refreshes and rebuilds.
    std::vector<std::string> trackedSelectedIdentityKeys_; // Set of identityKey values for selected processes; restore the selection after a refresh following Ctrl-selection.
    int trackedSelectedColumn_ = 0;          // Index of the currently selected column; preserve the user's focus column as much as possible when restoring currentItem.
    std::vector<ks::process::SystemThreadRecord> threadRecordList_; // Cache of the most recent refresh results for the thread page.
    std::unordered_map<std::string, ks::process::ThreadCounterSample> threadCounterSampleByIdentity_; // Thread CPU differential baseline.
    std::string threadDiagnosticText_;       // Diagnostic text from the most recent refresh of the thread page.
    std::unordered_set<std::uint32_t> hiddenProcessPidSet_; // The set of PIDs hidden by R0 in this session.
    std::vector<ksword::ark::ProcessCrossViewEntry> processCrossViewCache_; // R0 process cross-view cache.
    std::vector<ksword::ark::ThreadCrossViewEntry> threadCrossViewCache_; // R0 thread cross-view cache.
    ksword::ark::ProcessCrossViewResult lastProcessCrossViewResult_; // Most recent process cross-view metadata.
    ksword::ark::ThreadCrossViewResult lastThreadCrossViewResult_; // Most recent thread cross-view metadata.
    bool crossViewRefreshInProgress_ = false; // Cross-View background query mutex flag.
    std::uint64_t crossViewRefreshTicket_ = 0; // Cross-View query sequence number.

    // ======== Right-click menu binding status ========
    std::string contextActionIdentityKey_;      // The identityKey bound to the current menu action.
    ks::process::ProcessRecord contextActionRecord_{}; // Fallback copy when identity becomes invalid during refresh.
    std::vector<ProcessActionTarget> contextActionRecords_; // Multi-selected process copies bound to the right-click menu.
    bool hasContextActionRecord_ = false;
    bool contextMenuVisible_ = false;           // Freezes periodic refresh during menu popup.
    std::uint32_t threadContextActionTid_ = 0;  // TID bound to the thread context menu.
    std::uint32_t threadContextActionPid_ = 0;  // PID bound to the thread context menu.
    bool threadContextMenuVisible_ = false;     // Freeze thread refresh during thread menu popup.

    // ======== Thread Refresh Scheduling ========
    bool threadRefreshInProgress_ = false;      // Whether the thread page has an ongoing background refresh task.
    std::uint64_t threadRefreshTicket_ = 0;     // Thread page refresh sequence number (used to discard stale results).
    bool initialRefreshScheduled_ = false;      // Whether the first refresh was scheduled upon initial display.
};

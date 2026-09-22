#pragma once

// ============================================================
// DiskMonitorPage.h
// Purpose:
// 1) Provides a dedicated 'Disk Monitor' page under the 'Hardware' Dock.
// 2) Use process I/O counters to implement resource monitor-style process selection and disk activity aggregation;
// 3) Enable Microsoft-Windows-Kernel-File ETW file-level aggregation; explicitly report file-level collection unavailable on failure.
// ============================================================

#include "../Framework.h"
#include "DiskMonitorStoragePanel.h"

#include <QHash>
#include <QIcon>
#include <QWidget>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include <atomic>         // std::atomic_bool: Controls the exit of the background ETW thread.
#include <cstdint>        // std::uint32_t/std::uint64_t: PID, byte count, and timestamp.
#include <memory>         // std::unique_ptr: Manages the background ETW thread.
#include <mutex>          // std::mutex: Protects the ETW aggregation table.
#include <thread>         // std::thread: Background ETW real-time session.
#include <unordered_map>  // std::unordered_map: Stores process counter baselines across sampling cycles.
#include <unordered_set>  // std::unordered_set: Store the set of user-selected PIDs.
#include <vector>         // std::vector: Hold sampling results and sort for display.

class QCheckBox;
class QLabel;
class QLineEdit;
class QPushButton;
class QSplitter;
class QTableWidget;
class QTableWidgetItem;
class QTimer;
class QToolButton;
class QVBoxLayout;
struct _EVENT_RECORD;

// DiskMonitorPage:
// - Input: Qt parent control;
// - Processing: Periodically enumerate process IO_COUNTERS to calculate read/write/total rates. Show all file activity when selection is empty; filter by PID when checked.
// - Returns: This control has no business return value; results are displayed directly in the table.
class DiskMonitorPage final : public QWidget
{
    Q_OBJECT

public:
    // Constructor:
    // - parent: Qt parent object;
    // - initialize UI, connect signals, and start a 1-second refresh timer.
    explicit DiskMonitorPage(QWidget* parent = nullptr);

    // Destructor:
    // - Stop refresh timer;
    // - Qt child objects are released by the parent-child tree.
    ~DiskMonitorPage() override;

private:
    // ProcessDiskSample：
    // - Purpose: Store single-process disk I/O sampling for the current round and the difference from the previous two rounds.
    // - Handling: raw* fields come from GetProcessIoCounters; rate* fields are calculated from historical samples.
    // - Note: These counters cover process file/device I/O transfer volume, not equivalent to physical disk write volume;
    // - Return: The struct itself has no return value.
    struct ProcessDiskSample
    {
        std::uint32_t pid = 0;                 // pid: Process ID.
        QString processName;                   // processName: Process name.
        QString processImagePath;              // processImagePath: Process path; may be empty if access is denied.
        std::uint32_t threadCount = 0;          // threadCount: Process thread count.
        std::uint64_t rawReadBytes = 0;         // rawReadBytes: cumulative bytes read.
        std::uint64_t rawWriteBytes = 0;        // rawWriteBytes: cumulative written transfer bytes.
        std::uint64_t rawOtherBytes = 0;        // rawOtherBytes: Cumulative bytes transferred for other I/O operations.
        std::uint64_t rawReadOps = 0;           // rawReadOps: Cumulative read count.
        std::uint64_t rawWriteOps = 0;          // rawWriteOps: cumulative write count
        std::uint64_t rawOtherOps = 0;          // rawOtherOps: cumulative other I/O operations.
        QString ioPriorityText;                 // ioPriorityText: The process's current I/O priority; empty if permissions are insufficient.
        double readBytesPerSec = 0.0;           // readBytesPerSec: read bytes per second.
        double writeBytesPerSec = 0.0;          // writeBytesPerSec: Write rate in bytes per second.
        double totalBytesPerSec = 0.0;          // totalBytesPerSec: Total read/write bytes per second.
        double readOpsPerSec = 0.0;             // readOpsPerSec: Read operations per second.
        double writeOpsPerSec = 0.0;            // writeOpsPerSec: Write operations per second.
        double otherBytesPerSec = 0.0;          // otherBytesPerSec: Other I/O bytes per second.
        double responseTimeMs = 0.0;            // responseTimeMs: Estimated average response time based on throughput/number of operations.
        bool countersReady = false;             // countersReady: whether dynamic counters were successfully read.
        bool rateReady = false;                 // rateReady: Whether historical samples are available to calculate the rate.
    };

    // ProcessDiskBaseline：
    // - Purpose: Saves the original cumulative value from the last sample.
    // - Processing: Use PID + creation time as identity to reduce PID reuse errors;
    // - Returns: nothing (struct).
    struct ProcessDiskBaseline
    {
        std::uint64_t identityCreateTime100ns = 0; // identityCreateTime100ns: Process creation time.
        std::uint64_t sampleTickMs = 0;            // sampleTickMs: Sample timestamp in milliseconds.
        std::uint64_t rawReadBytes = 0;            // rawReadBytes: Cumulative read bytes from the last time.
        std::uint64_t rawWriteBytes = 0;           // rawWriteBytes: cumulative bytes written last time.
        std::uint64_t rawOtherBytes = 0;           // rawOtherBytes: cumulative other bytes from the previous iteration.
        std::uint64_t rawReadOps = 0;              // rawReadOps: cumulative read count from last time
        std::uint64_t rawWriteOps = 0;             // rawWriteOps: Cumulative write count since last check.
        std::uint64_t rawOtherOps = 0;             // rawOtherOps: Cumulative count of other operations from the last time.
    };

    // FileActivitySample：
    // - Purpose: Stores 1-second activity aggregated by PID + file path from Kernel-File ETW events.
    // - Handling: read/write fields come from real-time ETW byte accumulation; process name and I/O priority are filled in by the collection pipeline.
    // - Returns: The structure is used for UI display only and holds no system resources.
    struct FileActivitySample
    {
        std::uint32_t pid = 0;             // pid: Process ID triggering file I/O.
        QString processName;               // processName: Process name.
        QString processImagePath;          // processImagePath: Used for active table process icons and filtering.
        QString filePath;                  // filePath: File path parsed from ETW.
        double readBytesPerSec = 0.0;      // readBytesPerSec: file read rate.
        double writeBytesPerSec = 0.0;     // writeBytesPerSec: File write rate.
        QString ioPriorityText;            // ioPriorityText: I/O priority text; displays "Unknown" if the priority is unknown.
        double responseTimeMs = 0.0;       // responseTimeMs: Average response time when available via ETW.
        bool responseAvailable = false;    // responseAvailable: Indicates whether there is a real/event field response time.
        std::uint32_t eventCount = 0;       // eventCount: Aggregated ETW event count within this window.
    };

    // FileActivityAccumulator：
    // - Purpose: Accumulate file activity for the current refresh window within the ETW callback thread;
    // - Processing: UI thread swaps and clears every second, converting to FileActivitySample;
    // - Note: The structure does not return data.
    struct FileActivityAccumulator
    {
        std::uint32_t pid = 0;                  // pid: Process ID.
        QString filePath;                       // filePath: File path.
        std::uint64_t readBytes = 0;            // readBytes: Bytes read within the window.
        std::uint64_t writeBytes = 0;           // writeBytes: Bytes written within the window.
        QString ioPriorityText;                 // ioPriorityText: The most recently available I/O priority within the window.
        double responseMsTotal = 0.0;           // responseMsTotal: Cumulative response time.
        std::uint32_t responseCount = 0;        // responseCount: Number of response time samples.
        std::uint32_t eventCount = 0;           // eventCount: Event count.
    };

    // FileActivityStateEntry：
    // - Purpose: Maintain a unique, continuously updated activity row for the same PID + file path;
    // - Handling: Overwrite with the latest window rate each round; remove if idle beyond the retention window or the process exits.
    // - Return: The structure is used only for maintaining activity state within the UI thread and does not directly return system resources.
    struct FileActivityStateEntry
    {
        std::uint64_t lastActivityMs = 0;        // lastActivityMs: Monotonic timestamp of the most recent read/write start or completion.
        FileActivitySample sample;               // sample: display value for the current refresh window of this logical activity.
    };

    // PendingFileIoOperation：
    // - Purpose: Save temporary state between the Read/Write initiation event and the OperationEnd completion event;
    // - Handling: Associate start/end with IRP pointer; upon completion, write actual elapsed time back to file activity aggregation.
    // - Returns: The structure is used solely as a callback thread cache and is not returned externally.
    struct PendingFileIoOperation
    {
        std::uint32_t pid = 0;                  // pid: Process ID initiating I/O.
        QString filePath;                       // filePath: File path resolved when initiating I/O.
        QString ioPriorityText;                 // ioPriorityText: The priority text resolved when initiating I/O.
        std::uint64_t startTime100ns = 0;       // startTime100ns: ETW timestamp; when ClientContext=2, the unit is 100ns.
    };

    // ===================== UI Initialization =====================
    void initializeUi();
    void initializeConnections();
    void configureTableWidget(QTableWidget* tableWidget, int processIdColumn = -1) const;

    // startInitialSampling:
    // - Input: none; called with a delay by QTimer after construction;
    // - Processing: Start file ETW, perform the first round of process I/O sampling, and start the periodic timer.
    // - Returns: None. Repeated calls are intercepted by m_initialSamplingStarted.
    void startInitialSampling();

    // ===================== Sampling and Refreshing =====================
    void refreshNow();
    void applyProcessDiskSamples(
        std::vector<ProcessDiskSample> sampleList,
        DiskMonitorStorageBatch storageSampleBatch);
    std::vector<ProcessDiskSample> collectProcessDiskSamples();
    std::vector<FileActivitySample> consumeFileActivitySamples(const std::vector<ProcessDiskSample>& sampleList);
    void pruneStaleSelection(const std::vector<ProcessDiskSample>& sampleList);
    void updateProcessTable(const std::vector<ProcessDiskSample>& sampleList);
    void updateActivityTable();
    void updateSummaryLabels(const std::vector<ProcessDiskSample>& sampleList);
    void syncSelectionFromTable();

    // installProcessColumnMenu：
    // - Inputs: None;
    // - Processing: Add a per-column show/hide menu to the process table header, with all fields displayed by default.
    // - Returns: Nothing.
    void installProcessColumnMenu();

    // ===================== ETW file activity collection =====================
    void startFileActivityEtw();
    void stopFileActivityEtw();
    static void WINAPI fileActivityEtwCallback(struct _EVENT_RECORD* eventRecordPointer);
    void handleFileActivityEtwEvent(const struct _EVENT_RECORD* eventRecordPointer);

    // ===================== Table Utilities =====================
    QTableWidgetItem* createReadOnlyItem(const QString& text) const;
    QTableWidgetItem* createNumericItem(const QString& text, double numericValue) const;
    void setTableItemText(
        QTableWidget* tableWidget,
        int rowIndex,
        int columnIndex,
        QTableWidgetItem* itemPointer) const;
    void applyProcessRowCheckState(QTableWidgetItem* checkItem, std::uint32_t pid) const;
    QString processSearchText(const ProcessDiskSample& sample) const;
    bool sampleMatchesFilter(const ProcessDiskSample& sample) const;
    bool activityMatchesFilter(const FileActivitySample& sample) const;
    QIcon processIconForPath(const QString& imagePath);

    // ===================== Formatting Utilities =====================
    QString formatBytesPerSecond(double bytesPerSecond) const;
    QString formatBytes(double bytesValue) const;
    QString formatOpsPerSecond(double opsPerSecond) const;
    QString formatMilliseconds(double milliseconds) const;

private:
    QVBoxLayout* rootLayout_ = nullptr;           // m_rootLayout: Root layout.
    QLabel* titleLabel_ = nullptr;                // m_titleLabel: Title label.
    QLabel* statusLabel_ = nullptr;               // m_statusLabel: Refresh status label.
    QLabel* summaryLabel_ = nullptr;              // m_summaryLabel: Total read/write rate summary.
    QLineEdit* filterEdit_ = nullptr;             // m_filterEdit: Process filter input box.
    QCheckBox* onlyActiveCheckBox_ = nullptr;     // m_onlyActiveCheckBox: Show only active IO processes.
    QPushButton* refreshButton_ = nullptr;        // m_refreshButton: Manual refresh button.
    QPushButton* selectActiveButton_ = nullptr;   // m_selectActiveButton: Checkbox to select the currently active process.
    QPushButton* clearSelectionButton_ = nullptr; // m_clearSelectionButton: Button to clear selections.
    QSplitter* splitter_ = nullptr;               // m_splitter: Vertical splitter for tables.
    QToolButton* processSectionButton_ = nullptr; // m_processSectionButton: Collapsed header for process activity.
    QToolButton* activitySectionButton_ = nullptr;// m_activitySectionButton: Collapsed header for file activity.
    QToolButton* storageSectionButton_ = nullptr; // m_storageSectionButton: Storage section collapse header.
    QTableWidget* processTable_ = nullptr;        // m_processTable: Process-level disk rate table.
    QTableWidget* activityTable_ = nullptr;       // m_activityTable: Disk activity table filtered by all or selected PIDs.
    DiskMonitorStoragePanel* storagePanel_ = nullptr; // m_storagePanel: Fixed volume capacity and performance section.
    QTimer* refreshTimer_ = nullptr;              // m_refreshTimer: Periodic refresh timer.
    bool initialSamplingStarted_ = false;         // m_initialSamplingStarted: Whether ETW and the first sampling round have started.
    std::unique_ptr<std::thread> processSamplingThread_; // m_processSamplingThread: Background thread for process I/O sampling.
    std::atomic_bool processSamplingInProgress_{ false }; // m_processSamplingInProgress: Prevents overlapping sampling.
    std::atomic_bool processSamplingStopRequested_{ false }; // m_processSamplingStopRequested: Cooperative cancellation of synchronous sampling during destruction.

    std::unordered_map<std::uint32_t, ProcessDiskBaseline> baselineByPid_; // m_baselineByPid: PID to historical baseline.
    std::unordered_set<std::uint32_t> selectedPidSet_; // m_selectedPidSet: User-selected PID set.
    std::vector<ProcessDiskSample> lastSampleList_;    // m_lastSampleList: The result from the most recent sampling.
    std::vector<FileActivitySample> lastFileActivityList_; // m_lastFileActivityList: Unique PID+path status rows within the recent activity window.
    QHash<QString, FileActivityStateEntry> fileActivityStateByKey_; // m_fileActivityStateByKey: Maps PID + normalized path to a unique persistent activity row.
    std::unordered_map<std::uint32_t, QString> recentProcessNameByPid_; // Recent process name cache: supplements short-term ETW history.
    std::unordered_map<std::uint32_t, QString> recentProcessPathByPid_; // Recent image path cache: to complete active icons.
    QHash<QString, QIcon> processIconByPath_;      // UI cache mapping image paths to 16px shell icons.
    bool updatingProcessTable_ = false;                // m_updatingProcessTable: Prevents recursive check synchronization triggered by program refresh.

    std::unique_ptr<std::thread> fileActivityEtwThread_; // m_fileActivityEtwThread: Background ETW session thread.
    std::atomic_bool fileActivityEtwStopRequested_{ false }; // m_fileActivityEtwStopRequested: Stop request.
    std::atomic_bool fileActivityEtwRunning_{ false };       // m_fileActivityEtwRunning: Whether ETW is currently receiving events.
    std::atomic<std::uint64_t> fileActivityEtwSessionHandle_{ 0 }; // m_fileActivityEtwSessionHandle: StartTrace session handle.
    std::atomic<std::uint64_t> fileActivityEtwTraceHandle_{ 0 };   // m_fileActivityEtwTraceHandle: OpenTrace read handle.
    std::atomic<std::uint32_t> fileActivityEtwLastStatus_{ 0 };    // m_fileActivityEtwLastStatus: The most recent ETW status code.
    std::mutex fileActivityMutex_;                           // m_fileActivityMutex: Protects the following ETW aggregation cache.
    std::unordered_map<std::uint64_t, QString> filePathByObject_; // m_filePathByObject: Mapping from FileObject/FileKey to file path.
    std::unordered_map<std::uint64_t, PendingFileIoOperation> pendingFileIoByIrp_; // m_pendingFileIoByIrp: Mapping from IRP to pending I/O operations.
    QHash<QString, FileActivityAccumulator> fileActivityByKey_;   // m_fileActivityByKey: PID + file path aggregation table.
    std::uint64_t lastFileActivityDrainMs_ = 0;              // m_lastFileActivityDrainMs: timestamp of the last UI consumption of ETW aggregation.
};

#pragma once

// ============================================================
// ProcessTraceMonitorWidget.h
// Purpose:
// 1) Provides the first 'process-oriented monitoring' tab for the 'monitoring' module;
// 2) Allow users to select one or more target processes and maintain the target process tree at runtime.
// 3) Prioritize ETW with process snapshots as a supplement, preserving as many behavior events related to the target process as possible.
// 4) Provide interaction capabilities for event filtering, export, copy, and jumping to process details.
// ============================================================

#include "ProcessTraceTimelineWidget.h"
#include "../Framework.h"

#include <QWidget>

#include <atomic>         // std::atomic_bool: Background monitoring status control.
#include <cstddef>        // std::size_t: event queue capacity and batch size per refresh.
#include <cstdint>        // std::uint32_t/std::uint64_t: Fixed-width types for PID, timestamps, etc.
#include <deque>          // std::deque: Bounded FIFO queue for high-frequency ETW events.
#include <memory>         // std::unique_ptr: Managed by a background thread.
#include <mutex>          // std::mutex: Protects the pending event queue and runtime process tree.
#include <thread>         // std::thread: ETW session thread and auxiliary refresh thread.
#include <unordered_map>  // std::unordered_map: Save runtime process tree nodes by PID.
#include <vector>         // std::vector: target list, event cache, and Provider list.

class QCheckBox;
class QComboBox;
class QEvent;
class QHBoxLayout;
class QLabel;
class QLineEdit;
class QPushButton;
class QSplitter;
class QTableWidget;
class QTableWidgetItem;
class QTimer;
class QVBoxLayout;

struct _EVENT_RECORD;
class ProcessTraceMonitorWidget final : public QWidget
{
public:
    // Constructor:
    // - Purpose: initialize the target process selection area, control bar, event table, and filter.
    // - Parameter parent: Qt parent widget.
    explicit ProcessTraceMonitorWidget(QWidget* parent = nullptr);

    // Destructor:
    // - Purpose: Stops the background ETW session and auxiliary timer to ensure a thread-safe exit.
    ~ProcessTraceMonitorWidget() override;

public:
    // AvailableProcessColumn：
    // - Purpose: Define the column order for the "Available Process" table.
    // - Usage: Unified column index access when refreshing the available process list and filtering.
    enum AvailableProcessColumn
    {
        kAvailableProcessColumnPid = 0,
        kAvailableProcessColumnName,
        kAvailableProcessColumnPath,
        kAvailableProcessColumnUser,
        kAvailableProcessColumnCount
    };

    // TargetProcessColumn：
    // - Purpose: Define the column order for the "Target Process" table.
    // - Call: Reused when refreshing the target list and displaying status.
    enum TargetProcessColumn
    {
        kTargetProcessColumnState = 0,
        kTargetProcessColumnPid,
        kTargetProcessColumnName,
        kTargetProcessColumnPath,
        kTargetProcessColumnUser,
        kTargetProcessColumnRemark,
        kTargetProcessColumnCount
    };

    // EventColumn：
    // - Purpose: Define the column order for the "Event" table.
    // - Usage: Unified column access for inserting events, right-click menus, and filtering logic.
    enum EventColumn
    {
        kEventColumnTime100ns = 0,
        kEventColumnType,
        kEventColumnProvider,
        kEventColumnEventId,
        kEventColumnEventName,
        kEventColumnPidTid,
        kEventColumnProcess,
        kEventColumnRootPid,
        kEventColumnRelation,
        kEventColumnDetail,
        kEventColumnActivityId,
        kEventColumnCount
    };

    // ProviderEntry：
    // - Purpose: Describes a successfully parsed ETW Provider.
    // - providerName: Provider display name;
    // - providerGuidText: Provider GUID text.
    // - providerTypeText: Event types defined in this project (process/file/network, etc.).
    struct ProviderEntry
    {
        QString providerName;
        QString providerGuidText;
        QString providerTypeText;
    };

    // TargetProcessEntry：
    // - Purpose: Stores the root process explicitly selected by the user for monitoring.
    // - pid: root process PID
    // - processName: root process name;
    // - imagePath: root process path;
    // - userName: the user owning the root process.
    // - creationTime100ns: creation time, used to distinguish PID reuse.
    // - alive: whether still alive in the current snapshot;
    // - remarkText: supplementary description, e.g., "manually added" or the error reason.
    struct TargetProcessEntry
    {
        std::uint32_t pid = 0;
        QString processName;
        QString imagePath;
        QString userName;
        std::uint64_t creationTime100ns = 0;
        bool alive = false;
        QString remarkText;
    };

    // RuntimeTrackedProcess：
    // - Purpose: Save any node within the runtime target process tree.
    // - pid: current node PID.
    // - parentPid: parent PID, used for display and tracking;
    // - rootPid: The root PID to which this node ultimately belongs;
    // - processName/imagePath: node name and path;
    // - creationTime100ns: Creation time, used for auxiliary confirmation.
    // - alive: whether the node still exists in the current snapshot;
    // - isRoot: Whether this node is the root node selected by the user.
    // - staleSnapshotRounds: the number of consecutive snapshot rounds where the node was not hit again, used for dead node cleanup.
    // - lastRelatedEventTime100ns: timestamp of the last hit by a related event, used for auditing and cleanup.
    struct RuntimeTrackedProcess
    {
        std::uint32_t pid = 0;
        std::uint32_t parentPid = 0;
        std::uint32_t rootPid = 0;
        QString processName;
        QString imagePath;
        std::uint64_t creationTime100ns = 0;
        bool alive = false;
        bool isRoot = false;
        std::uint32_t staleSnapshotRounds = 0;
        std::uint64_t lastRelatedEventTime100ns = 0;
    };

    // EtwPropertyValue：
    // - Purpose: Stores the parsed result of a single ETW top-level property.
    // - nameText: attribute name.
    // - valueText: human-readable text value.
    // - numericAvailable: whether parsing to a numeric value succeeded;
    // - numericValue: Numeric form, facilitating PID/ParentPid identification.
    struct EtwPropertyValue
    {
        QString nameText;
        QString valueText;
        bool numericAvailable = false;
        std::uint64_t numericValue = 0;
    };

    // CapturedEventRow：
    // - Purpose: Save a row of behavioral events pending UI refresh.
    // - time100nsText: Text representation of the 100ns timestamp;
    // - typeText: event type (process/file/registry/network, etc.);
    // - providerText: Provider name;
    // - eventId: event ID;
    // - eventName: event name;
    // - pidText: PID/TID text.
    // - processText: Associated process text
    // - rootPidText: Text representing the root PID ownership.
    // - relationText: Description of root process/child process/attribute associations, etc.
    // - detailText: summary of attributes and metadata.
    // - activityIdText: ActivityId text.
    struct CapturedEventRow
    {
        std::uint64_t time100ns = 0;
        QString time100nsText;
        QString typeText;
        QString providerText;
        int eventId = 0;
        QString eventName;
        QString pidText;
        QString processText;
        QString rootPidText;
        QString relationText;
        QString detailText;
        QString activityIdText;
    };

private:
    // event：
    // - Purpose: Listen for global palette/style changes and refresh the dynamic styles of custom Collapse controls on this page;
    // - Processing: Pass to QWidget base class first, then refresh the collapsed panel based on event type.
    // - Returns: The result of handling the event by QWidget::event.
    bool event(QEvent* eventPointer) override;

    // ========================= UI Initialization =========================
    void initializeUi();
    void initializeConnections();
    // createConfigurationCollapseSection：
    // - Purpose: Create the default expanded configuration collapse section for the process trace page.
    // - Parameters parentWidget, titleText, contentWidget, and expanded control the parent widget, title, content page, and initial state, respectively.
    // - Returns: A collapsible section QWidget that can be directly added to the root layout.
    QWidget* createConfigurationCollapseSection(
        QWidget* parentWidget,
        const QString& titleText,
        QWidget* contentWidget,
        bool expanded) const;
    void updateActionState();
    void updateStatusLabel();

    // ========================= Target Process Selection ======================
    void refreshAvailableProcessListAsync();
    void populateAvailableProcessTable(const std::vector<ks::process::ProcessRecord>& processList);
    void applyAvailableProcessFilter();
    void addSelectedAvailableProcesses();
    void addManualProcessByPid();
    void createSuspendedTargetProcess();
    void addTargetProcessByPid(std::uint32_t pidValue, const QString& sourceText);
    void updateTargetProcessRemarkByPid(std::uint32_t pidValue, const QString& remarkText);
    // upsertAutoTrackedProcessInTargetList：
    // - Purpose: Synchronize new child processes identified by ETW to the "monitored targets" list.
    // - Invocation: Called after the ETW thread returns to the UI thread via QueuedConnection;
    // - Input pidValue: Child process PID.
    // - Input parentPidValue: Parent PID that launched this child process.
    // - Parameters processNameText/processPathText: process name and path hints extracted from ETW attributes.
    // - Input parameter creationTime100ns: creation time (0 if ETW has not yet provided it);
    // - Output: None (internally updates m_targetProcessList and the target table).
    void upsertAutoTrackedProcessInTargetList(
        std::uint32_t pidValue,
        std::uint32_t parentPidValue,
        const QString& processNameText,
        const QString& processPathText,
        std::uint64_t creationTime100ns);
    // removeTrackedProcessFromTargetListByPid：
    // - Purpose: Automatically stop tracking from the monitored list when ETW explicitly reports a process exit;
    // - Invocation: Called after the ETW thread returns to the UI thread via QueuedConnection;
    // - Input parameter pidValue: The PID to be removed.
    // - Input reasonText: Reason for this removal (used for audit logging);
    // - Output: None (internally updates m_targetProcessList and the target table).
    void removeTrackedProcessFromTargetListByPid(
        std::uint32_t pidValue,
        const QString& reasonText);
    void refreshTargetTable();
    void removeSelectedTargetProcesses();
    void clearTargetProcesses();
    // showAvailableContextMenu：
    // - Purpose: Provides read-only copy and add-to-monitor-target menu for the "Available Processes" table.
    // - Call: triggered by the table's right-click CustomContextMenu signal;
    // - Input position: coordinates within the viewport; Output: none, menu actions directly update the clipboard or target list.
    void showAvailableContextMenu(const QPoint& position);
    void showTargetContextMenu(const QPoint& position);

    // ========================= Event Filtering and Export =====================
    void applyEventFilter();
    void clearEventFilter();
    void scheduleEventFilterApply();
    bool hasAnyEventFilterActive() const;
    void updateEventFilterStatusText(int visibleCount, int totalCount);
    // applyTimelineSelection：
    // - Purpose: Receive absolute start and end times from the timeline control.
    // - Processing: Record internal time selection and trigger filtering of the current event table;
    // - Returns: Nothing.
    void applyTimelineSelection(std::uint64_t start100ns, std::uint64_t end100ns);
    // refreshTimelineRange：
    // - Purpose: Update the left and right boundaries of the timeline based on the capture start/stop status.
    // - Input captureFinished: true indicates the right side is fixed to the stop time; false indicates the right side follows the current time.
    // - Returns: Nothing.
    void refreshTimelineRange(bool captureFinished);
    // refreshTimelinePoints：
    // - Purpose: Push the lightweight event point cache to the timeline control for repainting.
    // - Returns: Nothing.
    void refreshTimelinePoints();
    // isTimelineFilterActive：
    // - Purpose: Determine if the user has enabled additional time filtering via the timeline.
    // - Returns: true if applyEventFilter requires an additional time range check.
    bool isTimelineFilterActive() const;
    void flushPendingRows();
    void appendEventRow(const CapturedEventRow& rowValue);
    void openEventDetailViewerForRow(int row) const;
    void showEventContextMenu(const QPoint& position);
    void exportVisibleRowsToTsv();

    // ========================= Monitoring Flow ==========================
    void startMonitoring();
    void stopMonitoring();
    void stopMonitoringInternal(bool waitForThread);
    void setMonitoringPaused(bool paused);
    void refreshTrackedProcessSnapshotAsync();
    void seedTrackedProcessTree(const std::vector<ks::process::ProcessRecord>& processList);
    void syncTrackedProcessTree(const std::vector<ks::process::ProcessRecord>& processList);
    void pruneStaleTrackedProcesses();

    // ========================= ETW collection ==========================
    static void WINAPI processTraceEtwCallback(struct _EVENT_RECORD* eventRecordPtr);
    void enqueueEventFromRecord(const struct _EVENT_RECORD* eventRecordPtr);
    bool buildRelevantEventRow(
        const struct _EVENT_RECORD* eventRecordPtr,
        const QString& providerNameText,
        const QString& providerTypeText,
        const std::vector<EtwPropertyValue>& propertyList,
        CapturedEventRow* rowOut);
    bool extractEventProperties(
        const struct _EVENT_RECORD* eventRecordPtr,
        std::vector<EtwPropertyValue>* propertyListOut) const;
    QString buildEventDetailText(
        const QString& providerGuidText,
        const struct _EVENT_RECORD* eventRecordPtr,
        const std::vector<EtwPropertyValue>& propertyList) const;

    // ======================= Text and Style Helpers ========================
    static QString blueButtonStyle();
    static QString blueInputStyle();
    static QString blueHeaderStyle();
    static QString collapsePanelStyle();
    static QString collapseHeaderButtonStyle();
    static void refreshCollapseTheme(QWidget* rootWidget);
    static QString providerTypeFromName(const QString& providerNameText);
    static QString now100nsText();
    static std::uint64_t currentSystemTime100ns();
    static QString guidToText(const GUID& guidValue);
    static QString queryEtwEventName(const struct _EVENT_RECORD* eventRecordPtr);
    static bool textMatch(
        const QString& sourceText,
        const QString& patternText,
        bool useRegex,
        Qt::CaseSensitivity caseSensitivity);
    static bool tryParseUint32Text(const QString& textValue, std::uint32_t* valueOut);
    static QTableWidgetItem* createReadOnlyItem(const QString& textValue);

private:
    // ========================= Top-level Controls =========================
    QVBoxLayout* rootLayout_ = nullptr;                 // m_rootLayout: Root layout.
    QWidget* configurationCollapseWidget_ = nullptr;    // m_configurationCollapseWidget: Process-oriented configuration collapse section, expanded by default.
    QWidget* configurationPanel_ = nullptr;             // m_configurationPanel: Content page within the collapsed section holding process selection, control bar, and filters.
    QSplitter* topSplitter_ = nullptr;                  // m_topSplitter: Top left-right splitter.
    QWidget* availablePanel_ = nullptr;                 // m_availablePanel: Available processes panel.
    QWidget* targetPanel_ = nullptr;                    // m_targetPanel: Monitoring target panel.
    QWidget* controlPanel_ = nullptr;                   // m_controlPanel: Control panel.
    QWidget* filterPanel_ = nullptr;                    // m_filterPanel: Event filter panel.

    // ========================= Optional Process Area =======================
    QLineEdit* availableFilterEdit_ = nullptr;          // m_availableFilterEdit: Available process filter box.
    QPushButton* availableRefreshButton_ = nullptr;     // m_availableRefreshButton: Button to refresh the process list.
    QPushButton* createTargetButton_ = nullptr;         // m_createTargetButton: Button to create and suspend the monitoring target.
    QPushButton* addSelectedButton_ = nullptr;          // m_addSelectedButton: Button to add selected processes.
    QLineEdit* manualPidEdit_ = nullptr;                // m_manualPidEdit: Manual PID input box.
    QPushButton* addManualPidButton_ = nullptr;         // m_addManualPidButton: Button to add by PID.
    QLabel* availableStatusLabel_ = nullptr;            // m_availableStatusLabel: Optional process status text.
    QTableWidget* availableTable_ = nullptr;            // m_availableTable: Current system process table.

    // ========================= Monitoring Target Area ========================
    QPushButton* removeTargetButton_ = nullptr;         // m_removeTargetButton: Button to remove the selected target.
    QPushButton* clearTargetButton_ = nullptr;          // m_clearTargetButton: Clear target button.
    QLabel* targetStatusLabel_ = nullptr;               // m_targetStatusLabel: Target list status text.
    QTableWidget* targetTable_ = nullptr;               // m_targetTable: Monitored listening list (including manual targets and automatic child processes).

    // ========================= Control Bar ==========================
    QPushButton* startButton_ = nullptr;                // m_startButton: Start monitoring button.
    QPushButton* stopButton_ = nullptr;                 // m_stopButton: Stop monitoring button.
    QPushButton* pauseButton_ = nullptr;                // m_pauseButton: Pause/Resume button.
    QPushButton* exportButton_ = nullptr;               // m_exportButton: Export events button.
    QLabel* statusLabel_ = nullptr;                     // m_statusLabel: Overall monitoring status label.

    // ========================= Event Filtering Area =======================
    QComboBox* eventTypeCombo_ = nullptr;              // m_eventTypeCombo: Event type filter dropdown.
    QLineEdit* eventProviderFilterEdit_ = nullptr;     // m_eventProviderFilterEdit: Provider filter box.
    QLineEdit* eventProcessFilterEdit_ = nullptr;      // m_eventProcessFilterEdit: Process/root PID filter box.
    QLineEdit* eventNameFilterEdit_ = nullptr;         // m_eventNameFilterEdit: Event name filter input.
    QLineEdit* eventDetailFilterEdit_ = nullptr;       // m_eventDetailFilterEdit: Event detail filter input.
    QLineEdit* eventGlobalFilterEdit_ = nullptr;       // m_eventGlobalFilterEdit: Full-field filter box.
    QCheckBox* eventRegexCheck_ = nullptr;             // m_eventRegexCheck: Enable regular expressions.
    QCheckBox* eventCaseCheck_ = nullptr;              // m_eventCaseCheck: Case sensitivity.
    QCheckBox* eventInvertCheck_ = nullptr;            // m_eventInvertCheck: Whether to invert matching.
    QCheckBox* eventKeepBottomCheck_ = nullptr;        // m_eventKeepBottomCheck: Keep at bottom.
    QPushButton* eventClearFilterButton_ = nullptr;    // m_eventClearFilterButton: Clear filter button.
    QLabel* eventFilterStatusLabel_ = nullptr;         // m_eventFilterStatusLabel: Filter result statistics text.
    ProcessTraceTimelineWidget* eventTimelineWidget_ = nullptr; // m_eventTimelineWidget: ETW event waterfall timeline.
    QTableWidget* eventTable_ = nullptr;               // m_eventTable: Behavior event result table.

    // ========================= Background Status =========================
    std::vector<ks::process::ProcessRecord> availableProcessList_; // m_availableProcessList: Available process snapshot.
    std::vector<TargetProcessEntry> targetProcessList_;            // m_targetProcessList: List of root processes selected by the user.
    std::vector<ProviderEntry> activeProviderList_;                // m_activeProviderList: Providers successfully enabled in this monitoring round.
    std::unordered_map<std::uint32_t, RuntimeTrackedProcess> trackedProcessMap_; // m_trackedProcessMap: Runtime target process tree.
    static constexpr std::size_t kPendingRowCapacity = 24000;       // Maximum number of events to display; discard the oldest events when backlog occurs.
    static constexpr std::size_t kUiFlushRowLimit = 160;            // Maximum number of rows written per GUI tick.
    static constexpr int kUiFlushBudgetMs = 4;                       // Rendering time budget per GUI tick.

    std::deque<CapturedEventRow> pendingRows_;                     // m_pendingRows: Bounded FIFO queue of rows pending flush to UI in the background.
    std::vector<ProcessTraceTimelineEventPoint> timelineEventPoints_; // m_timelineEventPoints: Lightweight event cache for timeline rendering.
    std::mutex runtimeMutex_;                                      // m_runtimeMutex: Protects the target process tree and Provider list.
    std::mutex pendingMutex_;                                      // m_pendingMutex: Protects the pending event queue for refreshing.
    std::size_t pendingDroppedRows_ = 0;                            // m_pendingDroppedRows: Number of events dropped due to backlog protection.
    std::atomic_bool captureRunning_{ false };                     // m_captureRunning: Indicates whether the ETW listener is running.
    std::atomic_bool capturePaused_{ false };                      // m_capturePaused: Whether ETW listening is paused.
    std::atomic_bool captureStopFlag_{ false };                    // m_captureStopFlag: Background thread stop signal.
    std::atomic_bool availableRefreshPending_{ false };            // m_availableRefreshPending: Whether an optional process refresh is in progress.
    std::atomic_bool runtimeRefreshPending_{ false };              // m_runtimeRefreshPending: Indicates whether a runtime snapshot refresh is in progress.
    std::unique_ptr<std::thread> captureThread_;                   // m_captureThread: ETW session thread.
    QTimer* uiUpdateTimer_ = nullptr;                              // m_uiUpdateTimer: Timer for throttled refreshing of the event table.
    QTimer* eventFilterDebounceTimer_ = nullptr;                   // m_eventFilterDebounceTimer: Event filtering debounce timer.
    QTimer* runtimeRefreshTimer_ = nullptr;                        // m_runtimeRefreshTimer: Runtime snapshot auxiliary timer.
    int captureProgressPid_ = 0;                                   // m_captureProgressPid: Progress bar task ID.
    std::atomic<std::uint64_t> sessionHandle_{ 0 };                // m_sessionHandle: ETW session handle.
    std::atomic<std::uint64_t> traceHandle_{ 0 };                  // m_traceHandle: ETW consumer handle.
    std::uint64_t captureStartTime100ns_ = 0;                      // m_captureStartTime100ns: Start time of the current monitoring session.
    std::uint64_t captureStopTime100ns_ = 0;                       // m_captureStopTime100ns: Stop time for the current monitoring session.
    std::uint64_t timelineSelectionStart100ns_ = 0;                // m_timelineSelectionStart100ns: Start point of the timeline selection box.
    std::uint64_t timelineSelectionEnd100ns_ = 0;                  // m_timelineSelectionEnd100ns: End point of the timeline selection range.
    bool timelineUserSelectionActive_ = false;                     // m_timelineUserSelectionActive: Whether the user has enabled time-box selection.
    qint64 lastTimelineRefreshMs_ = 0;                             // m_lastTimelineRefreshMs: Time of the last event point copy to the timeline.
    QString sessionName_;                                          // m_sessionName: Name of the current ETW session.
};

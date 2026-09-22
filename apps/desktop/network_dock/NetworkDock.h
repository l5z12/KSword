#pragma once

// ============================================================
// NetworkDock.h
// Purpose:
// 1) Build the complete sidebar Tab UI for the "Network" Dock.
// 2) Display a table of all TCP/UDP packets in both send and receive directions.
// 3) Provide combined filtering (PID/IP range/port/packet length), process rate limiting, and packet detail inspection capabilities.
// 4) Provides TCP/UDP connection monitoring and TCP connection termination.
// 5) Provides a visualization parameter execution page for "manually constructed network requests".
// ============================================================

#include "../Framework.h"
#include "../monitor_dock/ProcessTraceTimelineWidget.h"
#include "../../../shared/platform/network/NetworkNids.h"

#include <QHash>
#include <QIcon>
#include <QPointer>
#include <QSet>
#include <QStringList>
#include <QThreadPool>
#include <QVector>
#include <QWidget>

#include <atomic>        // std::atomic_bool: Controls concurrent status for live host scanning.
#include <condition_variable> // std::condition_variable: Waits for scan tasks to exit during the destruction phase.
#include <cstdint>       // std::uint32_t/std::uint64_t: PID, sequence number, and length fields.
#include <deque>         // std::deque: Ordered packet sequence buffer and background refresh queue.
#include <memory>        // std::unique_ptr: Background monitoring service object management.
#include <mutex>         // std::mutex: Protects the shared queue between the background thread and the UI thread.
#include <optional>      // std::optional: Optional filter condition enable/disable status.
#include <unordered_map> // Sequence number to message entity cache, supporting detail lookup.
#include <utility>       // std::pair: expressing range filtering (min/max).
#include <vector>        // std::vector: Connection snapshot cache and temporary rendering array.

// Qt forward declaration: reduces header coupling and compilation overhead.
class QCheckBox;
class QComboBox;
class QHBoxLayout;
class QLabel;
class QLineEdit;
class QMenu;
class QPlainTextEdit;
class QProgressBar;
class QPushButton;
class QSpinBox;
class QTableWidget;
class QTabWidget;
class QTimer;
class QUrl;
class QVBoxLayout;
class QWidget;
class QShowEvent;
class QDialog;
class QCompleter;
class QScrollArea;
class QStandardItemModel;
class CodeEditorWidget;
class MultiThreadDownloadSegmentBarWidget;
class NetworkFirewallPage;
class NetworkAuditPage;

namespace ks::network
{
    struct HttpsProxyParsedEntry;
    class HttpsMitmProxyService;
}

// ============================================================
// NetworkDock
// Notes:
// - Packet capture and rate limiting capabilities are provided by ks::network::TrafficMonitorService;
// - Connection snapshots and manual request execution are provided by ks::network utility functions;
// - This class is responsible solely for UI rendering, filter management, user interaction, and log output.
// ============================================================
class NetworkDock final : public QWidget
{
    Q_OBJECT

public:
    // Constructor:
    // - Purpose: initialize the UI, bind background service callbacks, and connect interaction signals.
    // - Parameter parent: Qt parent widget, may be null.
    explicit NetworkDock(QWidget* parent = nullptr);

    // Destructor:
    // - Purpose: Stop the background packet capture thread to prevent asynchronous callbacks after the window is released.
    ~NetworkDock() override;

    // Switch to network audit TCP/UDP Cross-View and filter by PID set, independent of traffic monitoring rules.
    void focusConnectionsByPids(const QVector<quint32>& processIds);

    // setProcessDetailConnectionScope: When embedded in process details, display only the network audit Cross-View entry.
    void setProcessDetailConnectionScope();

protected:
    // showEvent：
    // - initialize the HTTPS proxy service instance only upon first display.
    // - Avoid constructing proxy-related objects prematurely during main window startup.
    void showEvent(QShowEvent* event) override;

private:
    // PacketTableColumn: definition of main traffic monitoring table column indices.
    enum class PacketTableColumn : int
    {
        kTime = 0,       // Packet capture time (millisecond precision).
        kProtocol,       // Protocol (TCP/UDP).
        kDirection,      // Direction (Outbound/Inbound).
        kSource,         // Data source (R0/R3).
        kPid,            // PID of the owning process.
        kProcessName,    // Process name (with icon).
        kLocalEndpoint,  // Local address:port.
        kRemoteEndpoint, // Remote address:port.
        kRemoteDomain,   // Remote domain (adjacent to remote endpoint, asynchronous resolution).
        kPacketSize,     // Total packet length (bytes).
        kPayloadSize,    // Payload size (in bytes).
        kPreview,        // Load preview (hexadecimal).
        kCount           // Total columns.
    };

    // RateLimitTableColumn: definition of rate limit rule table column indices.
    enum class RateLimitTableColumn : int
    {
        kPid = 0,            // Target PID.
        kProcessName,        // Target process name (snapshot query completion).
        kLimitKBps,          // Rate limit threshold (KB/s).
        kSuspendMs,          // Suspend duration exceeding limit (milliseconds).
        kTriggerCount,       // Trigger count.
        kCurrentWindowBytes, // Current window cumulative bytes.
        kState,              // Status (running/suspended).
        kCount               // Total columns.
    };

    // TcpConnectionTableColumn: Definition of columns for the TCP connection monitoring table.
    enum class TcpConnectionTableColumn : int
    {
        kState = 0,      // TCP state text.
        kPid,            // Associated PID.
        kProcessName,    // Process name (with icon).
        kLocalEndpoint,  // Local address:port.
        kRemoteEndpoint, // Remote address:port.
        kCount           // Total columns.
    };

    // UdpEndpointTableColumn: UDP endpoint monitoring table column definitions.
    enum class UdpEndpointTableColumn : int
    {
        kPid = 0,        // Associated PID.
        kProcessName,    // Process name (with icon).
        kLocalEndpoint,  // Local address:port.
        kCount           // Total columns.
    };

    // NidsAlertTableColumn: NIDS alert table column definitions.
    enum class NidsAlertTableColumn : int
    {
        kTime = 0,       // Alert time.
        kSeverity,       // Alert severity.
        kCategory,       // Alert category.
        kRule,           // Rule number.
        kProtocol,       // Protocol.
        kDirection,      // Direction
        kPid,            // Associated PID.
        kProcessName,    // Process name.
        kLocalEndpoint,  // Local endpoint.
        kRemoteEndpoint, // Remote endpoint.
        kDetail,         // Alert details.
        kCount           // Total columns.
    };

    // Range type alias:
    // - UInt32Range is used for IPv4 host-order ranges and packet length ranges;
    // - UInt16Range is used for port ranges.
    using UInt32Range = std::pair<std::uint32_t, std::uint32_t>;
    using UInt16Range = std::pair<std::uint16_t, std::uint16_t>;

    // MonitorTextRuleFieldKind: Enum for 'text list type' in the rule group.
    enum class MonitorTextRuleFieldKind : int
    {
        kLocalAddress = 0, // Local address list (supports CIDR, ranges, and single IPs).
        kRemoteAddress,    // Remote address list (supports CIDR, ranges, and single IPs).
        kLocalPort,        // Local port list (supports single port or range).
        kRemotePort,       // Remote port list (supports single port or range).
        kPacketSize        // Packet size list (supports single values/ranges, comma-separated).
    };

    // MonitorProcessTarget: process filter entry (PID + name + icon).
    struct MonitorProcessTarget
    {
        std::uint32_t pid = 0;
        QString processName;
        QIcon processIcon;
    };

    // MonitorProcessCandidate: Cache for PID input completion candidates.
    struct MonitorProcessCandidate
    {
        std::uint32_t pid = 0;
        QString processName;
        QString displayText;
        QString searchText;
        QIcon processIcon;
    };

    // MonitorTextRuleFieldUiState: UI and data state for address/port/packet length list fields.
    struct MonitorTextRuleFieldUiState
    {
        QString labelText;
        QLineEdit* inputEdit = nullptr;
        QPushButton* addButton = nullptr;
        QPushButton* clearButton = nullptr;
        QTableWidget* tableWidget = nullptr;
        QStringList valueList;
    };

    // MonitorFilterRuleGroupCompiled: Matchable filter conditions after compiling a single rule group (AND within group, OR between groups).
    struct MonitorFilterRuleGroupCompiled
    {
        int groupId = 0;
        bool enabled = true;
        std::vector<std::uint32_t> processIdList;
        std::vector<UInt32Range> localAddressRangeList;
        std::vector<UInt32Range> remoteAddressRangeList;
        std::vector<UInt16Range> localPortRangeList;
        std::vector<UInt16Range> remotePortRangeList;
        std::vector<UInt32Range> packetSizeRangeList;

        bool hasAnyCondition() const
        {
            return !processIdList.empty() ||
                !localAddressRangeList.empty() ||
                !remoteAddressRangeList.empty() ||
                !localPortRangeList.empty() ||
                !remotePortRangeList.empty() ||
                !packetSizeRangeList.empty();
        }
    };

    // MonitorFilterRuleGroupUiState: UI component and original input state for a single rule group.
    struct MonitorFilterRuleGroupUiState
    {
        int groupId = 0;
        QWidget* containerWidget = nullptr;
        QLabel* titleLabel = nullptr;
        QCheckBox* enabledCheck = nullptr;
        QPushButton* removeGroupButton = nullptr;

        QLineEdit* processInputEdit = nullptr;
        QCompleter* processCompleter = nullptr;
        QStandardItemModel* processSuggestionModel = nullptr;
        QPushButton* addProcessButton = nullptr;
        QPushButton* removeInvalidProcessButton = nullptr;
        QPushButton* clearProcessButton = nullptr;
        QTableWidget* processTable = nullptr;
        std::vector<MonitorProcessTarget> processTargetList;

        MonitorTextRuleFieldUiState localAddressField;
        MonitorTextRuleFieldUiState remoteAddressField;
        MonitorTextRuleFieldUiState localPortField;
        MonitorTextRuleFieldUiState remotePortField;
        MonitorTextRuleFieldUiState packetSizeField;
    };

    // PacketTimelineCaptureSession：
    // - Purpose: Record a continuous time period when the user actually starts monitoring;
    // - startUnixMs/endUnixMs use real Unix milliseconds, while baseStart100ns uses the compressed monitoring timeline.
    // - The actual wait time between stopping and restarting monitoring does not enter baseStart100ns.
    struct PacketTimelineCaptureSession
    {
        std::uint64_t startUnixMs = 0; // startUnixMs: Real start time of this monitoring session.
        std::uint64_t endUnixMs = 0; // endUnixMs: The actual end time of this monitoring session; 0 indicates it is still running.
        std::uint64_t baseStart100ns = 0; // baseStart100ns: Starting offset when mapping this session to the timeline.
    };

    // PacketTimelineRateBucket：
    // - Purpose: Aggregate upload/download bytes per compressed 'Nth second'.
    // - Upload uses outbound packets; download uses inbound packets.
    // - Render as two line charts after pushing to the timeline control.
    struct PacketTimelineRateBucket
    {
        std::uint64_t uploadBytes = 0; // uploadBytes: Cumulative outbound bytes for this second.
        std::uint64_t downloadBytes = 0; // downloadBytes: Cumulative inbound bytes for this second.
    };

private:
    // MultiThreadDownloadSegmentState：
    // - Purpose: Saves the progress state for a single download segment.
    // - For internal logic of the 'Multi-thread Download' page only.
    struct MultiThreadDownloadSegmentState
    {
        std::uint64_t rangeBeginByte = 0; // rangeBeginByte: Start byte of the segment (inclusive).
        std::uint64_t rangeEndByte = 0; // rangeEndByte: The end byte of the segment (inclusive).
        std::atomic<std::uint64_t> downloadedBytes{ 0 }; // downloadedBytes: Number of bytes downloaded for this segment.
        std::atomic_bool finished{ false }; // finished: Whether this segment has finished downloading.
        QString statusText = QStringLiteral("等待中"); // statusText: Status text for this segment.
        mutable std::mutex statusMutex; // statusMutex: Concurrency read/write lock for segmented status text.
    };

    // MultiThreadDownloadTaskState：
    // - Purpose: Save the download state, segment collection, and background thread state for a single task.
    // - For internal logic of the 'Multi-thread Download' page only.
    struct MultiThreadDownloadTaskState
    {
        int taskId = 0; // taskId: Task ID.
        QString urlText; // urlText: original download URL for the task.
        QString savePathText; // savePathText: final output file path for the task.
        QString fileNameText; // fileNameText: task file name.
        int requestedThreadCount = 1; // requestedThreadCount: Number of threads configured by the user.
        int actualThreadCount = 1; // actualThreadCount: The actual number of executing threads (adjusted according to server capabilities).
        bool supportsRange = false; // supportsRange: Whether the server supports Range-based chunked downloads.
        std::uint64_t totalBytes = 0; // totalBytes: Total byte count of the target file.
        std::atomic<std::uint64_t> downloadedBytes{ 0 }; // downloadedBytes: Cumulative bytes downloaded for the task.
        std::atomic_int runningWorkerCount{ 0 }; // runningWorkerCount: Number of download threads still running.
        std::atomic_bool finished{ false }; // finished: Whether the task is completed (success or failure).
        std::atomic_bool failed{ false }; // failed: whether the task ended in failure.
        std::atomic_bool cancelRequested{ false }; // cancelRequested: whether a cancellation request has been received for the task.
        std::atomic_bool canceled{ false }; // canceled: Whether the task was actively canceled by the user.
        std::atomic_bool pauseRequested{ false }; // pauseRequested: Whether the task was paused by the user.
        QString statusText = QStringLiteral("等待启动"); // statusText: Task status text.
        QString errorReasonText; // errorReasonText: Text describing the reason for task failure.
        mutable std::mutex statusMutex; // statusMutex: Concurrency protection lock for task status and error text.
        std::vector<std::shared_ptr<MultiThreadDownloadSegmentState>> segmentStateList; // segmentStateList: Task segment state list.
    };

private:
    // ========================= UI Initialization =========================
    // initializeUi：
    // - Purpose: initialize the root layout and sidebar Tab container.
    // - Returns: Nothing.
    void initializeUi();

    // initializeTrafficMonitorTab：
    // - Purpose: Build the 'Traffic Monitor' tab (control bar + combined filter bar + packet table).
    // - Returns: Nothing.
    void initializeTrafficMonitorTab();

    // initializeNidsTab：
    // - Purpose: Build the 'NIDS' tab (switch + level filtering + real-time alert table).
    // - Returns: Nothing.
    void initializeNidsTab();

    // initializeRateLimitTab：
    // - Purpose: Build the 'Process Rate Limiting' tab (rule input + rule table + action log).
    // - Returns: Nothing.
    void initializeRateLimitTab();

    // initializeConnectionManageTab：
    // - Purpose: Constructs the "Connection Management" page (TCP table/UDP table + connection control buttons).
    // - Returns: Nothing.
    void initializeConnectionManageTab();

    // initializeManualRequestTab：
    // - Purpose: Constructs the "Request Construction" page (manual API parameter editing + execution result output).
    // - Returns: Nothing.
    void initializeManualRequestTab();

    // initializeMultiThreadDownloadTab：
    // - Purpose: Build the 'Multi-thread Download' page (URL/path/thread count + task and segment progress).
    // - Returns: Nothing.
    void initializeMultiThreadDownloadTab();

    // initializeFirewallTab：
    // - Purpose: Build the 'Firewall' page (WFP historical events + real-time subscription).
    // - Returns: Nothing.
    void initializeFirewallTab();

    // initializeNetworkAuditTab：
    // - Purpose: Build the 'Network Audit' tab (TCP/UDP cross-view, AFD, WFP, NDIS, NSI).
    // - Returns: Nothing.
    void initializeNetworkAuditTab();

    // Route table: enumeration, editing, and persistent management for IPv4/IPv6.
    void initializeRouteTableTab();
    void refreshRouteTable();
    void addRouteEntry();
    void editSelectedRouteEntry();
    void deleteSelectedRouteEntry();

    // initializeArpCacheTab：
    // - Purpose: Build the "ARP Cache" page (display + edit).
    // - Returns: Nothing.
    void initializeArpCacheTab();

    // initializeDnsCacheTab：
    // - Purpose: Build the "DNS Cache" page (display + edit).
    // - Returns: Nothing.
    void initializeDnsCacheTab();

    // initializeAliveHostScanTab：
    // - Purpose: Construct the 'Alive Host Discovery' page (IP range ICMP scanning).
    // - Returns: Nothing.
    void initializeAliveHostScanTab();

    // initializeHostsFileEditorTab：
    // - Purpose: Constructs the 'hosts file editor' tab (full-screen text editor).
    // - Returns: Nothing.
    void initializeHostsFileEditorTab();

    // initializeHttpsAnalyzeTab：
    // - Purpose: Build the 'HTTPS Parsing' page (proxy control + certificate trust + parsing results).
    // - Returns: Nothing.
    void initializeHttpsAnalyzeTab();

    // initializeConnections：
    // - Purpose: Connect the signal/slot of the unified connection button, input box, and table.
    // - Returns: Nothing.
    void initializeConnections();

    // ========================= Packet Capture Control =========================
    // startTrafficMonitor：
    // - Purpose: Request the background service to start the packet capture thread.
    // - Returns: Nothing.
    void startTrafficMonitor();

    // stopTrafficMonitor：
    // - Purpose: Request the background service to stop the packet capture thread.
    // - Returns: Nothing.
    void stopTrafficMonitor();

    // refreshR0TrafficSnapshotAsync：
    // - Background incremental reading of real R0 WFP IPv4/IPv6 per-packet records based on cursor position.
    // - When initialProbe=true, it is used to select R0 or automatically fall back to R3.
    // - Return: None; results are posted to the UI thread.
    void refreshR0TrafficSnapshotAsync(std::uint64_t generation, bool initialProbe);

    // startR3TrafficMonitor：
    // - Start legacy R3 packet capture when R0 is unavailable;
    // - fallbackReason is displayed in the status bar to indicate the current data source;
    // - Returns: Nothing.
    void startR3TrafficMonitor(const QString& fallbackReason);

    // updateMonitorButtonState：
    // - Purpose: Refresh the Start/Stop button state based on m_monitorRunning.
    // - Returns: Nothing.
    void updateMonitorButtonState();

    // ========================= Packet Data Processing ======================
    // onPacketCaptured：
    // - Purpose: Process a packet capture record, write to cache, and decide whether to display based on filter status.
    // - Parameter packetRecord: packet record parsed by the background service.
    // - Returns: Nothing.
    void onPacketCaptured(const ks::network::PacketRecord& packetRecord);

    // processNidsPacket：
    // - Purpose: Send a single packet to the NIDS engine and append new alerts.
    // - Parameter packetRecord: packet record parsed by the background service.
    // - Returns: Nothing.
    void processNidsPacket(const ks::network::PacketRecord& packetRecord);

    // appendNidsAlertRow：
    // - Purpose: Append a single NIDS alert record to the end of the table.
    // - Parameter alertRecord: Alert to be displayed.
    // - Returns: Nothing.
    void appendNidsAlertRow(const ks::network::NidsAlert& alertRecord);

    // rebuildNidsAlertTable：
    // - Purpose: Rebuild the NIDS alert table based on the current level filter.
    // - Returns: Nothing.
    void rebuildNidsAlertTable();

    // clearNidsAlerts：
    // - Purpose: Clear NIDS alerts, statistics, and engine window status.
    // - Returns: Nothing.
    void clearNidsAlerts();

    // updateNidsStatusLabel：
    // - Purpose: Refresh the NIDS tab status and count summary.
    // - Returns: Nothing.
    void updateNidsStatusLabel();

    // nidsAlertPassesFilter：
    // - Purpose: Determine if the alert meets the current level filter.
    // - Parameter alertRecord: The alert to be evaluated.
    // - Returns: true = display; false = hide.
    bool nidsAlertPassesFilter(const ks::network::NidsAlert& alertRecord) const;

    // onStatusMessageArrived：
    // - Purpose: Displays background status text and synchronizes button states.
    // - Parameter statusText: Status message reported by the background thread.
    // - Returns: Nothing.
    void onStatusMessageArrived(const std::string& statusText);

    // onRateLimitActionArrived：
    // - Purpose: Handle rate limit action events and append them to the rate limit log area.
    // - Parameter actionEvent: Suspend/resume action information.
    // - Returns: Nothing.
    void onRateLimitActionArrived(const ks::network::RateLimitActionEvent& actionEvent);

    // appendPacketToMonitorTable：
    // - Purpose: Append a packet record to the end of the 'Traffic Monitor' main table.
    // - Parameter packetRecord: Packet to be appended.
    // - Returns: Nothing.
    void appendPacketToMonitorTable(const ks::network::PacketRecord& packetRecord);

    // scheduleDomainResolutionForPacket：
    // - Launch bounded thread pool for remote IP resolution, prioritizing the local DNS cache.
    // - Initiate the task only once for the same address and fill the results back into all corresponding rows.
    // - Returns: Nothing.
    void scheduleDomainResolutionForPacket(std::uint64_t sequenceId, const QString& remoteAddressText);

    // applyDomainResolutionResult：
    // - Cache asynchronous resolution results and update packet cache/table;
    // - Display '-' uniformly for empty results to avoid blocking the packet capture path.
    // - Returns: Nothing.
    void applyDomainResolutionResult(const QString& remoteAddressText, const QString& domainText);

    // rebuildMonitorTableByFilter：
    // - Purpose: Rebuild the main traffic table based on current combined filter conditions.
    // - Returns: Nothing.
    void rebuildMonitorTableByFilter();

    // trimOldestPacketWhenNeeded：
    // - Purpose: Remove the oldest packet when the cache exceeds the limit to constrain memory usage.
    // - Returns: Nothing.
    void trimOldestPacketWhenNeeded();

    // clearAllPacketRows：
    // - Purpose: Clear the cache and table rows, and clear the background refresh queue.
    // - Returns: Nothing.
    void clearAllPacketRows();

    // applyPacketTimelineSelection：
    // - Purpose: Receive the start and end times (in 100ns units) from the traffic timeline selection tool.
    // - Parameters start100ns/end100ns: Time axis selection boundaries, unit 100ns; caller may pass unsorted values.
    // - Return: None. Internally rebuilds the traffic table and refreshes the filter status hint.
    void applyPacketTimelineSelection(std::uint64_t start100ns, std::uint64_t end100ns);

    // resetPacketTimelineToCurrentRange：
    // - Purpose: Clear the timeline selection and rebuild the full display range based on the current packet buffer.
    // - Return: None. The caller is responsible for rebuilding the table as needed.
    void resetPacketTimelineToCurrentRange();

    // refreshPacketTimelineRange：
    // - Purpose: Update the left and right boundaries of the timeline based on the current packet buffer and capture status.
    // - Return: None. Skips directly if the control is null.
    void refreshPacketTimelineRange();

    // refreshPacketTimelinePoints：
    // - Purpose: Push lightweight packet point cache to the ETW-compatible timeline control for repainting.
    // - Returns: Nothing.
    void refreshPacketTimelinePoints();

    // isPacketTimelineFilterActive：
    // - Purpose: Check if the user has enabled time-window filtering via the timeline.
    // - Returns: true indicates that the traffic table requires time-range filtering overlay.
    bool isPacketTimelineFilterActive() const;

    // packetPassesTimelineFilter：
    // - Purpose: Determine if a single packet falls within the current timeline selection range.
    // - Parameter packetRecord: Packet to be evaluated;
    // - Returns: true if the timeline allows display; false if filtered by the timeline.
    bool packetPassesTimelineFilter(const ks::network::PacketRecord& packetRecord) const;

    // packetPassesTimelineFilter：
    // - Purpose: Determine if a packet falls within the current timeline selection range using the cached sequence ID timestamp;
    // - Parameter sequenceId: Packet sequence ID, used to read the compressed timeline cache.
    // - Parameter packetRecord: Packet to be evaluated;
    // - Returns: true if the timeline allows display; false if filtered by the timeline.
    bool packetPassesTimelineFilter(
        std::uint64_t sequenceId,
        const ks::network::PacketRecord& packetRecord) const;

    // beginPacketTimelineMonitorSession：
    // - Purpose: Register a new continuous monitoring session after the user successfully starts monitoring.
    // - Processing logic: Map the session start point to the current cumulative monitoring duration, excluding historical downtime intervals.
    // - Returns: Nothing.
    void beginPacketTimelineMonitorSession();

    // endPacketTimelineMonitorSession：
    // - Purpose: Close the current continuous monitoring session after the user stops monitoring.
    // - Processing logic: Accumulate the session runtime duration; subsequent sessions resume from this accumulated value.
    // - Returns: Nothing.
    void endPacketTimelineMonitorSession();

    // resetPacketTimelineClockForCurrentState：
    // - Purpose: Reset the compressed timeline clock when clearing the packet timeline.
    // - Processing logic: If monitoring is still running, restart the 0-second session from the current real time.
    // - Returns: Nothing.
    void resetPacketTimelineClockForCurrentState();

    // packetTimelineTimeForRecord：
    // - Purpose: Map actual packet capture time to a compressed timeline representing only the monitoring duration.
    // - Parameter packetRecord: Packet to be mapped.
    // - Returns: A compressed timestamp in 100ns units.
    std::uint64_t packetTimelineTimeForRecord(const ks::network::PacketRecord& packetRecord) const;

    // packetTimelineTimeForSequence：
    // - Purpose: Prefer reading cached compressed time by sequence ID; fall back to packet mapping if missing;
    // - Parameter sequenceId: Packet sequence ID;
    // - Parameter packetRecord: The packet entity used for backward mapping.
    // - Returns: A compressed timestamp in 100ns units.
    std::uint64_t packetTimelineTimeForSequence(
        std::uint64_t sequenceId,
        const ks::network::PacketRecord& packetRecord) const;

    // currentPacketTimelineEnd100ns：
    // - Purpose: Return the right boundary of the current compressed timeline.
    // - Processing logic: Grows in real-time based on the current session during operation; remains cumulative after stopping.
    // - Returns: A compressed timestamp in 100ns units.
    std::uint64_t currentPacketTimelineEnd100ns() const;

    // addPacketTimelineRateSample：
    // - Purpose: Add a single packet record to the upload/download rate bucket for the corresponding second.
    // - Parameter packetRecord: Packet entity.
    // - Parameter timelineTime100ns: Packet compressed time.
    // - Returns: Nothing.
    void addPacketTimelineRateSample(
        const ks::network::PacketRecord& packetRecord,
        std::uint64_t timelineTime100ns);

    // removePacketTimelineRateSample：
    // - Purpose: Deduct the deleted packet from the rate bucket when trimming the cache.
    // - Parameter packetRecord: Packet entity.
    // - Parameter timelineTime100ns: Packet compressed time.
    // - Returns: Nothing.
    void removePacketTimelineRateSample(
        const ks::network::PacketRecord& packetRecord,
        std::uint64_t timelineTime100ns);

    // refreshPacketTimelineRatePoints：
    // - Purpose: Convert per-second rate buckets into upload/download line charts renderable by the timeline control.
    // - Returns: Nothing.
    void refreshPacketTimelineRatePoints();

    // ========================= Traffic Filtering ==========================
    // applyMonitorFilters：
    // - Purpose: Compile rule group configurations into matchable conditions and apply them to the traffic table.
    // - Returns: Nothing.
    void applyMonitorFilters();

    // clearMonitorFilters：
    // - Purpose: Clear all rule group configurations and restore display of the full packet set.
    // - Returns: Nothing.
    void clearMonitorFilters();

    // updateMonitorFilterStateLabel：
    // - Purpose: Aggregate current rule group filter status into the status label.
    // - Returns: Nothing.
    void updateMonitorFilterStateLabel();

    // addMonitorFilterRuleGroup：
    // - Purpose: Add a new rule group (OR between groups).
    // - Returns: Nothing.
    void addMonitorFilterRuleGroup();

    // removeMonitorFilterRuleGroup：
    // - Purpose: Delete the specified rule group.
    // - Parameter groupId: Unique ID of the rule group.
    // - Returns: Nothing.
    void removeMonitorFilterRuleGroup(int groupId);

    // rebuildMonitorFilterRuleGroupUi：
    // - Purpose: Rebuild the rule group area UI based on the current rule group status.
    // - Returns: Nothing.
    void rebuildMonitorFilterRuleGroupUi();

    // refreshProcessSuggestionModelForGroup：
    // - Purpose: Refresh the process candidate dropdown for the specified rule group based on the input keyword.
    // - Parameter groupId: Unique ID of the rule group.
    // - Parameter keywordText: Current input text.
    // - Returns: Nothing.
    void refreshProcessSuggestionModelForGroup(int groupId, const QString& keywordText);

    // refreshMonitorProcessCandidateList：
    // - Purpose: Refresh the 'System Process Candidate Cache' (PID/Name/Icon).
    // - Parameter forceRefresh: when true, ignore the minimum refresh interval.
    // - Returns: Nothing.
    void refreshMonitorProcessCandidateList(bool forceRefresh);

    // addProcessTargetByInput：
    // - Purpose: Parse the current value from the process input box and add it to the rule group's process list.
    // - Parameter groupId: Unique ID of the rule group.
    // - Returns: Nothing.
    void addProcessTargetByInput(int groupId);

    // removeProcessTarget：
    // - Purpose: Remove a single process entry from the rule group by PID.
    // - Parameter groupId: Unique ID of the rule group.
    // - Parameter pidValue: Target PID.
    // - Returns: Nothing.
    void removeProcessTarget(int groupId, std::uint32_t pidValue);

    // clearProcessTargetList：
    // - Purpose: Clear all process entries in the rule group.
    // - Parameter groupId: Unique ID of the rule group.
    // - Returns: Nothing.
    void clearProcessTargetList(int groupId);

    // removeInvalidProcessTargets：
    // - Purpose: Removes entries where the PID does not exist or the PID does not match the process name.
    // - Parameter groupId: Unique ID of the rule group.
    // - Returns: Nothing.
    void removeInvalidProcessTargets(int groupId);

    // addTextFilterItemsByInput：
    // - Purpose: Parse input box text into one or more entries and add them to the field list.
    // - Parameter groupId: Unique ID of the rule group.
    // - Parameter fieldKind: Field type (address/port/packet length).
    // - Returns: Nothing.
    void addTextFilterItemsByInput(int groupId, MonitorTextRuleFieldKind fieldKind);

    // removeTextFilterItem：
    // - Purpose: Delete a single entry from the field list.
    // - Parameter groupId: Unique ID of the rule group.
    // - Parameter fieldKind: field type.
    // - Parameter itemIndex: Item index.
    // - Returns: Nothing.
    void removeTextFilterItem(int groupId, MonitorTextRuleFieldKind fieldKind, int itemIndex);

    // clearTextFilterItems：
    // - Purpose: Clear all entries in the field list.
    // - Parameter groupId: Unique ID of the rule group.
    // - Parameter fieldKind: field type.
    // - Returns: Nothing.
    void clearTextFilterItems(int groupId, MonitorTextRuleFieldKind fieldKind);

    // refreshProcessTableForGroup：
    // - Purpose: Refresh the display of the 'Process List' table for the specified rule group.
    // - Parameter groupId: Unique ID of the rule group.
    // - Returns: Nothing.
    void refreshProcessTableForGroup(int groupId);

    // refreshTextTableForGroup：
    // - Purpose: Refresh the table for the specified rule group fields (address/port/packet length).
    // - Parameter groupId: Unique ID of the rule group.
    // - Parameter fieldKind: field type.
    // - Returns: Nothing.
    void refreshTextTableForGroup(int groupId, MonitorTextRuleFieldKind fieldKind);

    // clearAllMonitorFilterConfigurations：
    // - Purpose: One-click clear all rule groups and their entries, retaining one empty rule group.
    // - Returns: Nothing.
    void clearAllMonitorFilterConfigurations();

    // importMonitorFilterConfigFromUserSelectedPath：
    // - Purpose: Imports rule groups from a user-selected configuration file.
    // - Returns: Nothing.
    void importMonitorFilterConfigFromUserSelectedPath();

    // exportMonitorFilterConfigToUserSelectedPath：
    // - Purpose: Export the current rule group to a user-selected path.
    // - Returns: Nothing.
    void exportMonitorFilterConfigToUserSelectedPath() const;

    // loadMonitorFilterConfigFromDefaultPath：
    // - Purpose: Read rule groups from the default path `config/wireshark.cfg`.
    // - Returns: Nothing.
    void loadMonitorFilterConfigFromDefaultPath();

    // saveMonitorFilterConfigToDefaultPath：
    // - Purpose: Saves the current rule group to the default path `config/wireshark.cfg`.
    // - Returns: Nothing.
    void saveMonitorFilterConfigToDefaultPath() const;

    // saveMonitorFilterConfigToPath：
    // - Purpose: Saves the current rule group to the specified path.
    // - Parameter filePath: Target configuration file path.
    // - Parameter showErrorDialog: Whether to show a dialog box on failure.
    // - Returns: true on success; false on failure.
    bool saveMonitorFilterConfigToPath(const QString& filePath, bool showErrorDialog) const;

    // loadMonitorFilterConfigFromPath：
    // - Purpose: Load rule groups from the specified path and refresh the UI.
    // - Parameter filePath: Path to the source configuration file.
    // - Parameter showErrorDialog: Whether to show a dialog box on failure.
    // - Returns: true on success; false on failure.
    bool loadMonitorFilterConfigFromPath(const QString& filePath, bool showErrorDialog);

    // monitorFilterConfigPath：
    // - Purpose: Retrieve the absolute path of the default rule configuration file.
    // - Returns: `<exe directory>/config/wireshark.cfg`.
    QString monitorFilterConfigPath() const;

    // tryCompileMonitorFilterGroups：
    // - Purpose: Compile UI raw entries into matchable conditions.
    // - Parameter compiledGroupsOut: outputs the compiled result on success.
    // - Parameter errorTextOut: Error text output on failure.
    // - Returns: true = compilation success; false = invalid entries exist.
    bool tryCompileMonitorFilterGroups(
        std::vector<MonitorFilterRuleGroupCompiled>& compiledGroupsOut,
        QString& errorTextOut) const;

    // packetMatchesMonitorFilterGroup：
    // - Purpose: Determine if a packet matches a single rule group (AND within the group).
    // - Parameter packetRecord: Packet to be matched.
    // - Parameter groupFilter: Compiled rule group.
    // - Returns: true = match; false = no match.
    bool packetMatchesMonitorFilterGroup(
        const ks::network::PacketRecord& packetRecord,
        const MonitorFilterRuleGroupCompiled& groupFilter) const;

    // findMonitorFilterRuleGroupById：
    // - Purpose: Find the UI state object by rule group ID.
    // - Parameter groupId: Unique ID of the rule group.
    // - Returns: Pointer to the found item; nullptr if not found.
    MonitorFilterRuleGroupUiState* findMonitorFilterRuleGroupById(int groupId);
    const MonitorFilterRuleGroupUiState* findMonitorFilterRuleGroupById(int groupId) const;

    // findTextRuleField：
    // - Purpose: Locate the field state object by field type within a rule group.
    // - Parameter groupState: Target rule group.
    // - Parameter fieldKind: field type.
    // - Returns: Pointer to the found item; nullptr if not found.
    MonitorTextRuleFieldUiState* findTextRuleField(
        MonitorFilterRuleGroupUiState& groupState,
        MonitorTextRuleFieldKind fieldKind);
    const MonitorTextRuleFieldUiState* findTextRuleField(
        const MonitorFilterRuleGroupUiState& groupState,
        MonitorTextRuleFieldKind fieldKind) const;

    // addOrTrackProcessPid：
    // - Purpose: Inject a PID into the first rule group and immediately apply filtering.
    // - Parameter pidValue: Target PID.
    // - Returns: Nothing.
    void addOrTrackProcessPid(std::uint32_t pidValue);

    // splitMonitorFilterTokens：
    // - Purpose: Split input text by comma, semicolon, or whitespace.
    // - Parameter inputText: Original input text.
    // - Returns: Tokenized result (empty items removed).
    static QStringList splitMonitorFilterTokens(const QString& inputText);

    // tryParsePacketSizeToken：
    // - Purpose: Parse a single packet size condition (e.g., "40" or "60-80").
    // - Parameter tokenText: Input token.
    // - Parameter rangeOut: Output range upon successful parsing.
    // - Parameter normalizeTextOut: Output normalized text upon successful parsing.
    // - Returns: true = success; false = failure.
    static bool tryParsePacketSizeToken(
        const QString& tokenText,
        UInt32Range& rangeOut,
        QString& normalizeTextOut);

    // trackProcessByTableRow：
    // - Purpose: When right-clicking 'Track this process', write the PID of that row to the filter and apply it immediately.
    // - Parameter row: The index of the currently selected row.
    // - Returns: Nothing.
    void trackProcessByTableRow(int row);

    // gotoProcessDetailByTableRow：
    // - Purpose: Open an independent process details window when right-clicking 'Go to Process Details'.
    // - Parameter row: The index of the currently selected row.
    // - Returns: Nothing.
    void gotoProcessDetailByTableRow(int row);

    // ========================= Process Rate Limiting =========================
    // applyOrUpdateRateLimitRule：
    // - Purpose: Add or update rate limit rules for the specified PID.
    // - Returns: Nothing.
    void applyOrUpdateRateLimitRule();

    // removeSelectedRateLimitRule：
    // - Purpose: Delete the rule corresponding to the currently selected row in the rate limit rule table.
    // - Returns: Nothing.
    void removeSelectedRateLimitRule();

    // clearAllRateLimitRules：
    // - Purpose: Clear all rate limit rules (with confirmation dialog).
    // - Returns: Nothing.
    void clearAllRateLimitRules();

    // refreshRateLimitTable：
    // - Purpose: Rebuild the rate limit rule table using a background snapshot.
    // - Returns: Nothing.
    void refreshRateLimitTable();

    // appendRateLimitActionLogLine：
    // - Purpose: Append a line of text to the rate-limit action log window.
    // - Parameter logLine: log content.
    // - Returns: Nothing.
    void appendRateLimitActionLogLine(const QString& logLine);

    // ========================= Connection Management =========================
    // refreshConnectionTables：
    // - Purpose: Refresh the TCP and UDP connection monitoring tables.
    // - Returns: Nothing.
    void refreshConnectionTables();
    void applyConnectionSnapshot(
        std::vector<ks::network::TcpConnectionRecord> tcpSnapshot,
        std::vector<ks::network::UdpEndpointRecord> udpSnapshot,
        bool tcpOk,
        bool udpOk,
        std::string tcpErrorText,
        std::string udpErrorText);

    // refreshTcpConnectionTable：
    // - Purpose: Fetch TCP connection snapshot and rebuild the TCP table.
    // - Returns: Nothing.
    void refreshTcpConnectionTable();

    // refreshUdpEndpointTable：
    // - Purpose: Fetch UDP endpoint snapshot and rebuild the UDP table.
    // - Returns: Nothing.
    void refreshUdpEndpointTable();

    // terminateSelectedTcpConnection：
    // - Purpose: Terminate the currently selected TCP connection in the table (DELETE_TCB).
    // - Returns: Nothing.
    void terminateSelectedTcpConnection();

    // copySelectedConnectionRowToClipboard：
    // - Purpose: Copy the currently selected entire row of the connection table to the clipboard.
    // - Parameter tableWidget: Connection table object.
    // - Returns: Nothing.
    void copySelectedConnectionRowToClipboard(QTableWidget* tableWidget);

    // ========================= Request Construction =========================
    // executeManualRequest：
    // - Purpose: Read UI construction parameters, execute a manual network request, and output the result.
    // - Returns: Nothing.
    void executeManualRequest();

    // replayPacketToManualRequestByTableRow：
    // - Purpose: Quickly fill packet from specified table row into 'Request Construction' page to create an editable replay draft.
    // - Parameter row: Target row number in the packet capture list.
    // - Returns: Nothing.
    void replayPacketToManualRequestByTableRow(int row);

    // resetManualRequestForm：
    // - Purpose: Reset the request construction page to default parameters.
    // - Returns: Nothing.
    void resetManualRequestForm();

    // appendManualRequestLogLine：
    // - Purpose: Append a line of text with a timestamp prefix to the request construction result box.
    // - Parameter logLine: output content.
    // - Returns: Nothing.
    void appendManualRequestLogLine(const QString& logLine);

    // ======================= Multi-threaded Download ========================
    // startMultiThreadDownloadTask：
    // - Purpose: Create and start a download task based on the current URL, save directory, and thread count.
    // - Returns: Nothing.
    void startMultiThreadDownloadTask();

    // browseMultiThreadDownloadDirectory：
    // - Purpose: Select the download output directory and fill it back into the directory input box.
    // - Returns: Nothing.
    void browseMultiThreadDownloadDirectory();

    // loadMultiThreadDownloadCaptureSettings：
    // - Purpose: Read the 'clipboard auto-capture download links' setting and sync it to the multi-threaded download page controls.
    // - Usage: Called after the multi-threaded download page UI is constructed.
    // - Returns: Nothing.
    void loadMultiThreadDownloadCaptureSettings();

    // saveMultiThreadDownloadCaptureSettings：
    // - Purpose: Write the 'automatically capture download links from clipboard' setting to a JSON file;
    // - Invocation: Called after the settings control changes.
    // - Returns: Nothing.
    void saveMultiThreadDownloadCaptureSettings();

    // onMultiThreadDownloadClipboardChanged：
    // - Purpose: Handle system clipboard text changes and attempt to identify downloadable links.
    // - Invocation: Called when the QClipboard::changed(Clipboard) signal is triggered.
    // - Returns: Nothing.
    void onMultiThreadDownloadClipboardChanged();

    // showMultiThreadDownloadClipboardPrompt：
    // - Purpose: Confirms download URL and save directory via a non-blocking dialog.
    // - Invocation: Called when the clipboard recognizes a URL with a matching suffix.
    // - Parameter urlText: Candidate download URL text.
    // - Returns: Nothing.
    void showMultiThreadDownloadClipboardPrompt(const QString& urlText);

    // startMultiThreadDownloadTaskFromInput：
    // - Purpose: Inject external URL/directory input into the UI and reuse existing startup logic.
    // - Invocation: Called after the user clicks the "Start Download" button in the clipboard inquiry dialog.
    // - Input parameter urlText: Confirmed download URL.
    // - Input parameter saveDirectoryText: the confirmed save directory.
    // - Returns: true = new task successfully created; false = startup failed or task not created.
    bool startMultiThreadDownloadTaskFromInput(
        const QString& urlText,
        const QString& saveDirectoryText);

    // isMultiThreadDownloadClipboardUrlSupported：
    // - Purpose: Determine if the current URL can trigger an automatic download prompt based on the current suffix rules.
    // - Invocation: Called internally by the clipboard detection process.
    // - Input parameter urlObject: The parsed URL object;
    // - Returns: true if the suffix matches; false otherwise.
    bool isMultiThreadDownloadClipboardUrlSupported(const QUrl& urlObject) const;

    // refreshMultiThreadDownloadUi：
    // - Purpose: Refresh the download task table, chunk table, and total progress bar display.
    // - Returns: Nothing.
    void refreshMultiThreadDownloadUi();

    // findMultiThreadDownloadTaskById：
    // - Purpose: Find download task state object by task ID.
    // - Parameter taskId: Task ID.
    // - Returns: Shared pointer if found; otherwise returns null.
    std::shared_ptr<MultiThreadDownloadTaskState> findMultiThreadDownloadTaskById(int taskId) const;

    // setMultiThreadDownloadTaskPaused：
    // - Purpose: Pause or resume a running multi-threaded download task by task ID.
    // - Parameter taskId: task ID; paused is true to pause, false to resume.
    // - Returns: No return value; tasks that are not found or have already ended are ignored directly.
    void setMultiThreadDownloadTaskPaused(int taskId, bool paused);

    // cancelMultiThreadDownloadTask：
    // - Purpose: Request cancellation of a running multi-threaded download task by task ID.
    // - Input parameter taskId: task ID;
    // - Returns: No return value; tasks that are not found or have already ended are ignored directly.
    void cancelMultiThreadDownloadTask(int taskId);

    // ========================= ARP/DNS/Live Hosts ======================
    // refreshArpCacheTable：
    // - Purpose: Refreshes the ARP cache table.
    // - Returns: Nothing.
    void refreshArpCacheTable();

    // addArpCacheEntry：
    // - Purpose: Add a static ARP mapping entry.
    // - Returns: Nothing.
    void addArpCacheEntry();

    // removeSelectedArpCacheEntry：
    // - Purpose: Delete the currently selected row in the ARP table.
    // - Returns: Nothing.
    void removeSelectedArpCacheEntry();

    // flushArpCache：
    // - Purpose: Flush the system ARP cache.
    // - Returns: Nothing.
    void flushArpCache();

    // refreshDnsCacheTable：
    // - Purpose: Refresh the DNS resolution cache list.
    // - Returns: Nothing.
    void refreshDnsCacheTable();

    // removeDnsCacheEntry：
    // - Purpose: Remove DNS cache entry by name.
    // - Returns: Nothing.
    void removeDnsCacheEntry();

    // flushDnsCache：
    // - Purpose: Flush the DNS cache.
    // - Returns: Nothing.
    void flushDnsCache();

    // startAliveHostScan：
    // - Purpose: Start live host scanning for a specified IP range.
    // - Returns: Nothing.
    void startAliveHostScan();

    // stopAliveHostScan：
    // - Purpose: Stop the current live host scan.
    // - Returns: Nothing.
    void stopAliveHostScan();

    // cancelAndWaitForAliveHostScan：
    // - Purpose: Request the ICMP scan to stop and wait for background coordination tasks and their workers to exit before destruction.
    // - Returns: Nothing.
    void cancelAndWaitForAliveHostScan();

    // appendAliveHostRow：
    // - Purpose: Append a row to the scan results table.
    // - Returns: Nothing.
    void appendAliveHostRow(
        const QString& ipText,
        bool alive,
        std::uint32_t rttMs,
        const QString& detailText);

    // ========================= HTTPS parsing ========================
    // startHttpsProxyService：
    // - Purpose: Start the local HTTPS proxy based on current listening parameters.
    // - Returns: Nothing.
    void startHttpsProxyService();

    // stopHttpsProxyService：
    // - Purpose: Stops the local HTTPS proxy and updates the status.
    // - Returns: Nothing.
    void stopHttpsProxyService();

    // ensureHttpsRootCertificateTrusted：
    // - Purpose: One-click generation and installation of a trusted root certificate (current user certificate store).
    // - Returns: Nothing.
    void ensureHttpsRootCertificateTrusted();

    // applyHttpsSystemProxy：
    // - Purpose: Redirect system proxy to a local HTTPS proxy port.
    // - Returns: Nothing.
    void applyHttpsSystemProxy();

    // clearHttpsSystemProxy：
    // - Purpose: Restore the system proxy configuration prior to applying HTTPS proxy settings on this page.
    // - Returns: Nothing.
    void clearHttpsSystemProxy();

    // captureHttpsSystemProxySnapshot：
    // - Purpose: Save the original value before modifying the current user's proxy item, so that only modifications made on this page are restored.
    // - Returns: true if saved or snapshot exists; false if read failed.
    bool captureHttpsSystemProxySnapshot(QString* errorTextOut);

    // persistHttpsSystemProxyRecoveryTransaction：
    // - Purpose: Persist the original five-tuple values before modifying the system proxy, then publish and persist the Pending flag;
    // - Returns: true = transaction persisted; false = not in a state safe for rewriting the proxy.
    bool persistHttpsSystemProxyRecoveryTransaction(
        const std::optional<std::uint32_t>& proxyEnable,
        const std::optional<std::uint32_t>& autoDetect,
        const std::optional<QString>& proxyServer,
        const std::optional<QString>& proxyOverride,
        const std::optional<QString>& autoConfigUrl,
        QString* errorTextOut) const;

    // loadHttpsSystemProxyRecoveryTransaction：
    // - Purpose: Read and strictly validate Pending recovery transactions at startup.
    // - Return: true = no transaction or snapshot valid; false = read/verification failed.
    bool loadHttpsSystemProxyRecoveryTransaction(
        bool* pendingOut,
        std::optional<std::uint32_t>* proxyEnableOut,
        std::optional<std::uint32_t>* autoDetectOut,
        std::optional<QString>* proxyServerOut,
        std::optional<QString>* proxyOverrideOut,
        std::optional<QString>* autoConfigUrlOut,
        QString* errorTextOut) const;

    // clearHttpsSystemProxyRecoveryTransaction：
    // - Purpose: Deletes the persistent transaction only after the original proxy value is written back and the WinINet refresh succeeds.
    // - Return: true if deleted and persisted successfully or if the record does not exist; false if the transaction must be retained.
    bool clearHttpsSystemProxyRecoveryTransaction(QString* errorTextOut) const;

    // recoverPendingHttpsSystemProxyTransaction：
    // - Purpose: Load persistent transactions left over from the last abnormal exit at startup and automatically restore the system proxy.
    // - Return: true if no pending transaction or recovery succeeded; false if transaction is corrupted or recovery failed.
    bool recoverPendingHttpsSystemProxyTransaction(
        bool* recoveredOut,
        QString* errorTextOut);

    // restoreHttpsSystemProxySnapshot：
    // - Purpose: Restore the current user proxy entries saved before applying the HTTPS proxy on this page.
    // - Returns: true on success; false on failure.
    bool restoreHttpsSystemProxySnapshot(QString* errorTextOut);

    // onHttpsProxyParsedEntryArrived：
    // - Purpose: Receive proxy layer parsing results and write them to the table.
    // - Parameter parsedEntry: A single parsed record.
    // - Returns: Nothing.
    void onHttpsProxyParsedEntryArrived(const ks::network::HttpsProxyParsedEntry& parsedEntry);

    // openHttpsParsedDetailByRow：
    // - Purpose: Open the detail window based on the HTTPS parsing table row number.
    // - Parameter row: The HTTPS parsing table row index.
    // - Returns: Nothing.
    void openHttpsParsedDetailByRow(int row);

    // appendHttpsProxyLogLine：
    // - Purpose: Append a timestamped text line to the HTTPS page log output box.
    // - Parameter logLine: log content.
    // - Returns: Nothing.
    void appendHttpsProxyLogLine(const QString& logLine);

    // updateHttpsProxyStatusLabel：
    // - Purpose: Uniformly refresh the HTTPS proxy status label text.
    // - Parameter statusText: Status description text.
    // - Returns: Nothing.
    void updateHttpsProxyStatusLabel(const QString& statusText);

    // applyHttpsParsedTableFilter：
    // - Purpose: Filter the HTTPS parsed table by keyword and event type; affects display results only.
    // - Returns: Nothing.
    void applyHttpsParsedTableFilter();

    // clearHttpsParsedEntries：
    // - Purpose: Clear the HTTPS parsed table and corresponding detail cache.
    // - Returns: Nothing.
    void clearHttpsParsedEntries();

    // exportVisibleHttpsParsedEntries：
    // - Purpose: Export currently filtered HTTPS parsed entries to UTF-8 CSV.
    // - Returns: Nothing.
    void exportVisibleHttpsParsedEntries();

    // updateHttpsParsedSummary：
    // - Purpose: Refresh the visible row count and request/response/error statistics in the HTTPS parsing table.
    // - Returns: Nothing.
    void updateHttpsParsedSummary();

    // flushPendingPacketsToUi：
    // - Purpose: Batch consume background packet backlog and refresh the UI.
    // - Note: Throttling via timer to prevent lag caused by high-frequency per-packet updates.
    // - Returns: Nothing.
    void flushPendingPacketsToUi();

    // ========================= Packet Detail Window ======================
    // openPacketDetailWindowFromTableRow：
    // - Purpose: Extract packet sequence ID from the table row and open the detail window.
    // - Parameter tableWidget: Pointer to the source table.
    // - Parameter row: target row index.
    // - Returns: Nothing.
    void openPacketDetailWindowFromTableRow(QTableWidget* tableWidget, int row);

    // openPacketDetailWindowBySequenceId：
    // - Purpose: Look up the packet by sequence ID in the cache and open an independent detail window.
    // - Parameter sequenceId: Packet primary key sequence number.
    // - Returns: Nothing.
    void openPacketDetailWindowBySequenceId(std::uint64_t sequenceId);

    // ========================= Common Helper Functions ========================
    // toPacketColumn：
    // - Purpose: Convert packet column enums to int column indices.
    // - Parameter column: Packet table column enumeration value.
    // - Returns: The corresponding column index.
    static int toPacketColumn(PacketTableColumn column);

    // toRateLimitColumn：
    // - Purpose: Convert rate limit column enum to int column index.
    // - Parameter column: Rate limit table column enumeration value.
    // - Returns: The corresponding column index.
    static int toRateLimitColumn(RateLimitTableColumn column);

    // toTcpConnectionColumn：
    // - Purpose: Convert the TCP connection column enum to an int column index.
    // - Parameter column: TCP connection column enumeration value.
    // - Returns: The corresponding column index.
    static int toTcpConnectionColumn(TcpConnectionTableColumn column);

    // toUdpEndpointColumn：
    // - Purpose: Convert UDP endpoint column enum to int column index.
    // - Parameter column: UDP endpoint column enumeration value.
    // - Returns: The corresponding column index.
    static int toUdpEndpointColumn(UdpEndpointTableColumn column);

    // toNidsAlertColumn：
    // - Purpose: Convert NIDS alert column enum to an int column index.
    // - Parameter column: NIDS alert column enumeration value.
    // - Returns: The corresponding column index.
    static int toNidsAlertColumn(NidsAlertTableColumn column);

    // tryParsePidText：
    // - Purpose: Parse decimal PID text.
    // - Parameter pidText: input text.
    // - Parameter pidOut: Output PID upon successful parsing.
    // - Returns: true = success; false = failure.
    static bool tryParsePidText(const QString& pidText, std::uint32_t& pidOut);

    // tryParseUnsignedIntegerText：
    // - Purpose: Parse unsigned integer text in decimal or 0x hexadecimal format.
    // - Parameter integerText: Input text.
    // - Parameter valueOut: Output value upon successful parsing.
    // - Returns: true = success; false = failure.
    static bool tryParseUnsignedIntegerText(const QString& integerText, std::uint32_t& valueOut);

    // resolveProcessIconByPid：
    // - Purpose: Resolve and cache process icon by PID.
    // - Parameter processId: Target process PID.
    // - Parameter processName: Process name (used for fallback logging hints).
    // - Returns: an icon suitable for a table cell.
    QIcon resolveProcessIconByPid(std::uint32_t processId, const std::string& processName);

    // packetPassesMonitorFilter：
    // - Purpose: Determine if the packet satisfies all currently enabled filter conditions.
    // - Parameter packetRecord: Packet to be evaluated.
    // - Returns: true = passed; false = filtered.
    bool packetPassesMonitorFilter(const ks::network::PacketRecord& packetRecord) const;

    // packetPassesMonitorFilter：
    // - Purpose: Determine if the packet with the specified sequence ID satisfies all currently enabled filter conditions.
    // - Parameter sequenceId: Packet sequence number, used for stable reading of compressed timeline time;
    // - Parameter packetRecord: Packet to be evaluated;
    // - Returns: true = passed; false = filtered.
    bool packetPassesMonitorFilter(
        std::uint64_t sequenceId,
        const ks::network::PacketRecord& packetRecord) const;

private:
    // ========================= Top-level Layout =========================
    QVBoxLayout* rootLayout_ = nullptr;   // Root layout, hosting only the sidebar tab container.
    QTabWidget* sideTabWidget_ = nullptr; // Sidebar Tab (West).

    // ========================= Tab1: Traffic Monitoring ====================
    QWidget* trafficMonitorPage_ = nullptr;      // Traffic monitoring page container.
    QVBoxLayout* trafficMonitorLayout_ = nullptr;// Main layout for the traffic monitoring page.
    QHBoxLayout* monitorControlLayout_ = nullptr;// Packet capture control layout.
    QHBoxLayout* monitorFilterHeaderLayout_ = nullptr; // Filter panel header (funnel/button group).
    QWidget* monitorFilterPanel_ = nullptr;            // Container for the collapsed filter rule group panel.
    QVBoxLayout* monitorFilterPanelLayout_ = nullptr;  // Main layout for the filter rule group panel.
    QScrollArea* monitorFilterScrollArea_ = nullptr;   // Scroll container for rule groups.
    QWidget* monitorFilterGroupHostWidget_ = nullptr;  // Container for rule groups.
    QVBoxLayout* monitorFilterGroupHostLayout_ = nullptr; // Layout for rule groups.

    QPushButton* startMonitorButton_ = nullptr; // Start monitor button.
    QPushButton* stopMonitorButton_ = nullptr;  // Stop monitor button.
    QPushButton* clearPacketButton_ = nullptr;  // Clear packet button.
    QPushButton* networkPluginButton_ = nullptr; // Menu button for the network target plugin.
    QMenu* networkPluginMenu_ = nullptr;         // Dynamically discover plugins with targets=network.
    QLabel* monitorStatusLabel_ = nullptr;      // Packet capture status label.

    QPushButton* monitorFilterToggleButton_ = nullptr;     // Funnel button (expand/collapse filter configuration).
    QPushButton* addMonitorFilterGroupButton_ = nullptr;   // Add rule group button.
    QPushButton* applyMonitorFilterButton_ = nullptr;      // Apply filter button.
    QPushButton* clearMonitorFilterButton_ = nullptr;      // Button to clear all configurations with one click.
    QPushButton* saveMonitorFilterButton_ = nullptr;       // Button to save to the default cfg.
    QPushButton* importMonitorFilterButton_ = nullptr;     // Import configuration button.
    QPushButton* exportMonitorFilterButton_ = nullptr;     // Export configuration button.
    QLabel* monitorFilterStateLabel_ = nullptr;            // Current filter status summary label.
    ProcessTraceTimelineWidget* packetTimelineWidget_ = nullptr; // Traffic monitoring page timeline (reuses the ETW box-selection interaction control).
    QTableWidget* packetTable_ = nullptr;             // Table for all packets sent.

    // ========================= Tab2：NIDS ====================
    QWidget* nidsPage_ = nullptr;            // NIDS page container.
    QVBoxLayout* nidsLayout_ = nullptr;      // Main layout for the NIDS page.
    QHBoxLayout* nidsControlLayout_ = nullptr; // NIDS control bar layout.
    QCheckBox* nidsEnableCheck_ = nullptr;   // NIDS real-time detection switch.
    QComboBox* nidsSeverityFilterCombo_ = nullptr; // Alert severity filter.
    QPushButton* nidsClearButton_ = nullptr; // Clear NIDS alert button.
    QLabel* nidsStatusLabel_ = nullptr;      // NIDS running status label.
    QTableWidget* nidsAlertTable_ = nullptr; // NIDS alert table.

    // ========================= Tab3: Process Rate Limiting ====================
    QWidget* rateLimitPage_ = nullptr;           // Process rate limit page container.
    QVBoxLayout* rateLimitLayout_ = nullptr;     // Main layout for the process rate-limiting page.
    QHBoxLayout* rateLimitControlLayout_ = nullptr; // Rate limit control layout.
    QLineEdit* rateLimitPidEdit_ = nullptr;      // Input field for the rate-limit target PID.
    QSpinBox* rateLimitKBpsSpin_ = nullptr;      // Input field for the rate-limit threshold (KB/s).
    QSpinBox* rateLimitSuspendMsSpin_ = nullptr; // Input for suspension duration after exceeding the limit.
    QPushButton* applyRateLimitButton_ = nullptr;// Button to add/update rules.
    QPushButton* removeRateLimitButton_ = nullptr;// Button to remove the selected rule.
    QPushButton* clearRateLimitButton_ = nullptr; // Clear all rules button.
    QTableWidget* rateLimitTable_ = nullptr;      // Rate limit rule table.
    QPlainTextEdit* rateLimitLogOutput_ = nullptr;// Rate limit action log output box.

    // ========================= Tab3: Connection Management ====================
    QWidget* connectionManagePage_ = nullptr;      // Connection management page container.
    QVBoxLayout* connectionManageLayout_ = nullptr;// Main layout for the connection management page.
    QHBoxLayout* connectionControlLayout_ = nullptr;// Connection management control layout.
    QPushButton* refreshConnectionButton_ = nullptr; // Manual refresh connection snapshot button.
    QPushButton* autoRefreshConnectionButton_ = nullptr; // Auto-refresh toggle button (checkable).
    QPushButton* terminateTcpButton_ = nullptr;     // Terminates the selected TCP connection button.
    QPushButton* clearConnectionPidFilterButton_ = nullptr; // Clear cross-page PID connection filtering.
    QLabel* connectionStatusLabel_ = nullptr;       // Connection management status label.
    QTabWidget* connectionSubTabWidget_ = nullptr;  // Connection sub-tab (TCP/UDP).
    QTableWidget* tcpConnectionTable_ = nullptr;    // TCP connection monitoring table.
    QTableWidget* udpEndpointTable_ = nullptr;      // UDP endpoint monitoring table.
    QSet<quint32> connectionPidFilterSet_;          // Independent PID filter for 'Go to Network' injection from the Process page.

    // ========================= Tab4: Firewall ====================
    NetworkFirewallPage* firewallPage_ = nullptr;   // Firewall page container.

    // ========================= Tab4: Network Audit ====================
    NetworkAuditPage* networkAuditPage_ = nullptr;  // Network audit page container.

    // ========================= Tab5: Request Construction ====================
    QWidget* manualRequestPage_ = nullptr;          // Request construction page container.
    QVBoxLayout* manualRequestLayout_ = nullptr;    // Main layout for the request construction page.
    QComboBox* manualApiCombo_ = nullptr;           // API selection (TCP/UDP).
    QCheckBox* manualOverrideSocketParameterCheck_ = nullptr; // Whether socket parameters are manually overridden.
    QLineEdit* manualAddressFamilyEdit_ = nullptr;  // Address family input (AF_* values).
    QLineEdit* manualSocketTypeEdit_ = nullptr;     // socket type input (SOCK_* numeric value).
    QLineEdit* manualProtocolEdit_ = nullptr;       // protocol input (IPPROTO_* values).
    QLineEdit* manualSocketFlagsEdit_ = nullptr;    // WSASocket flags input.
    QCheckBox* manualEnableBindCheck_ = nullptr;    // Whether to bind the local endpoint first.
    QLineEdit* manualLocalAddressEdit_ = nullptr;   // Local address input.
    QSpinBox* manualLocalPortSpin_ = nullptr;       // Local port input.
    QLineEdit* manualRemoteAddressEdit_ = nullptr;  // Remote address input.
    QSpinBox* manualRemotePortSpin_ = nullptr;      // Remote port input.
    QCheckBox* manualConnectBeforeSendCheck_ = nullptr; // Whether to connect before sending.
    QCheckBox* manualReuseAddressCheck_ = nullptr;  // SO_REUSEADDR switch.
    QCheckBox* manualNoDelayCheck_ = nullptr;       // TCP_NODELAY switch.
    QSpinBox* manualSendTimeoutSpin_ = nullptr;     // Send timeout (ms).
    QSpinBox* manualRecvTimeoutSpin_ = nullptr;     // Receive the timeout (ms).
    QComboBox* manualPayloadFormatCombo_ = nullptr; // Payload format (text/hex).
    QPlainTextEdit* manualPayloadEditor_ = nullptr; // Request payload input.
    QLineEdit* manualSendFlagsEdit_ = nullptr;      // send flags input.
    QLineEdit* manualReceiveFlagsEdit_ = nullptr;   // recv flags input.
    QCheckBox* manualReceiveAfterSendCheck_ = nullptr; // Whether to receive immediately after sending.
    QSpinBox* manualReceiveMaxBytesSpin_ = nullptr; // Maximum receive bytes limit.
    QCheckBox* manualShutdownSendCheck_ = nullptr;  // Whether to send shutdown (SD_SEND) after sending.
    QPushButton* manualExecuteButton_ = nullptr;    // Manual execution request button.
    QPushButton* manualResetButton_ = nullptr;      // Reset parameters button.
    QPlainTextEdit* manualResultOutput_ = nullptr;  // Manual result output box.

    // ========================= Tab5: Multi-threaded download ====================
    QWidget* multiThreadDownloadPage_ = nullptr;      // Multi-thread download page container.
    QVBoxLayout* multiThreadDownloadLayout_ = nullptr; // Main layout for the multi-threaded download page.
    QHBoxLayout* multiThreadDownloadControlLayout_ = nullptr; // Layout for the download parameter control bar.
    QLineEdit* multiDownloadUrlEdit_ = nullptr;       // Download URL input field.
    QLineEdit* multiDownloadSaveDirEdit_ = nullptr;   // Download directory input field.
    QSpinBox* multiDownloadThreadCountSpin_ = nullptr; // Download thread count input field.
    QCheckBox* multiDownloadAutoCaptureClipboardCheck_ = nullptr; // Switch for automatically capturing download links from the clipboard.
    QLineEdit* multiDownloadCaptureSuffixEdit_ = nullptr; // Auto-identify the suffix input box (supports separators: ; , space).
    QPushButton* multiDownloadSaveCaptureSettingsButton_ = nullptr; // Button to save capture settings to JSON.
    QPushButton* multiDownloadBrowseDirButton_ = nullptr; // Button to select the download directory.
    QPushButton* multiDownloadStartButton_ = nullptr; // Start download button.
    QLabel* multiDownloadStatusLabel_ = nullptr;      // Download status label.
    QTableWidget* multiDownloadTaskTable_ = nullptr;  // Download task overview table.
    QTableWidget* multiDownloadSegmentTable_ = nullptr; // Current task segment progress table.
    MultiThreadDownloadSegmentBarWidget* multiDownloadSegmentBar_ = nullptr; // Segmented total progress bar control.
    QLabel* multiDownloadTotalProgressLabel_ = nullptr; // Total progress percentage label.

public:
    // UI/write model for route entries. Retain pure value fields to avoid exposing Windows route structures to the header dependency chain.
    struct RouteRecord
    {
        int addressFamily = 0;
        QString destinationAddress;
        int prefixLength = 0;
        QString nextHopAddress;
        quint32 interfaceIndex = 0;
        QString interfaceName;
        quint32 metric = 0;
        quint32 protocol = 0;
        quint32 origin = 0;
        bool publish = false;
        bool immortal = false;
        quint32 age = 0;
        quint32 validLifetime = 0;
        quint32 preferredLifetime = 0;
        quint8 sitePrefixLength = 0;
    };

private:

    // ========================= Tab6: Route Table ====================
    QWidget* routeTablePage_ = nullptr;
    QVBoxLayout* routeTableLayout_ = nullptr;
    QHBoxLayout* routeTableControlLayout_ = nullptr;
    QPushButton* refreshRouteButton_ = nullptr;
    QPushButton* addRouteButton_ = nullptr;
    QPushButton* editRouteButton_ = nullptr;
    QPushButton* removeRouteButton_ = nullptr;
    QLabel* routeStatusLabel_ = nullptr;
    QTableWidget* routeTable_ = nullptr;
    std::vector<RouteRecord> routeRecordCache_;

    // ========================= Tab7: ARP Cache ====================
    QWidget* arpCachePage_ = nullptr;            // ARP cache page container.
    QVBoxLayout* arpCacheLayout_ = nullptr;      // ARP cache page layout.
    QHBoxLayout* arpCacheControlLayout_ = nullptr; // ARP control layout.
    QPushButton* refreshArpButton_ = nullptr;    // Refresh ARP button.
    QPushButton* addArpButton_ = nullptr;        // Add ARP button.
    QPushButton* removeArpButton_ = nullptr;     // Remove selected ARP button.
    QPushButton* flushArpButton_ = nullptr;      // Flush ARP button.
    QLabel* arpStatusLabel_ = nullptr;           // ARP status label.
    QTableWidget* arpTable_ = nullptr;           // ARP cache table.

    // ========================= Tab7: DNS Cache ====================
    QWidget* dnsCachePage_ = nullptr;            // DNS cache page container.
    QVBoxLayout* dnsCacheLayout_ = nullptr;      // DNS cache page layout.
    QHBoxLayout* dnsCacheControlLayout_ = nullptr; // DNS control panel layout.
    QPushButton* refreshDnsButton_ = nullptr;    // Refresh DNS button.
    QPushButton* removeDnsButton_ = nullptr;     // Remove DNS button.
    QPushButton* flushDnsButton_ = nullptr;      // Flush DNS button.
    QLineEdit* dnsEntryEdit_ = nullptr;          // DNS deletion entry input field.
    QLabel* dnsStatusLabel_ = nullptr;           // DNS status label.
    QTableWidget* dnsTable_ = nullptr;           // DNS cache table.

    // ========================= Tab8: Live Host Discovery ====================
    QWidget* aliveScanPage_ = nullptr;           // Container for the host liveness scan page.
    QVBoxLayout* aliveScanLayout_ = nullptr;     // Layout for the host liveness scan page.
    QHBoxLayout* aliveScanControlLayout_ = nullptr; // Alive scan control layout.
    QLineEdit* aliveScanStartIpEdit_ = nullptr;  // Input box for the starting IP address of the scan.
    QLineEdit* aliveScanEndIpEdit_ = nullptr;    // Scan end IP input field.
    QSpinBox* aliveScanTimeoutSpin_ = nullptr;   // ICMP timeout input box.
    QPushButton* startAliveScanButton_ = nullptr; // Start scan button.
    QPushButton* stopAliveScanButton_ = nullptr;  // Stop scan button
    QProgressBar* aliveScanProgressBar_ = nullptr; // Scan progress bar.
    QLabel* aliveScanStatusLabel_ = nullptr;     // Scan status label.
    QTableWidget* aliveScanTable_ = nullptr;     // Alive host results table.

    // ========================= Tab9: HTTPS Parsing ====================
    QWidget* httpsAnalyzePage_ = nullptr;          // HTTPS parsing page container.
    QVBoxLayout* httpsAnalyzeLayout_ = nullptr;    // Main layout for the HTTPS analysis page.
    QHBoxLayout* httpsAnalyzeControlLayout_ = nullptr; // HTTPS control bar layout.
    QLineEdit* httpsListenAddressEdit_ = nullptr;  // Proxy listen address input field.
    QSpinBox* httpsListenPortSpin_ = nullptr;      // Proxy listen port input field.
    QPushButton* httpsStartProxyButton_ = nullptr; // HTTPS proxy start button
    QPushButton* httpsStopProxyButton_ = nullptr;  // Stop HTTPS proxy button.
    QPushButton* httpsTrustCertButton_ = nullptr;  // One-click certificate trust button.
    QPushButton* httpsApplyProxyButton_ = nullptr; // Button to apply system proxy.
    QPushButton* httpsClearProxyButton_ = nullptr; // Clear system proxy button.
    QLabel* httpsProxyStatusLabel_ = nullptr;      // HTTPS proxy status label.
    QLineEdit* httpsParsedFilterEdit_ = nullptr;   // HTTPS parsing table keyword filter box.
    QComboBox* httpsParsedEventFilterCombo_ = nullptr; // HTTPS parsing table event type filter combo box.
    QPushButton* httpsClearParsedButton_ = nullptr;// HTTPS parsed result clear button.
    QPushButton* httpsExportParsedButton_ = nullptr;// HTTPS parsed result export button.
    QCheckBox* httpsAutoScrollCheck_ = nullptr;    // HTTPS parsing table auto-scroll toggle.
    QLabel* httpsParsedSummaryLabel_ = nullptr;    // HTTPS parsed summary label.
    QTableWidget* httpsParsedTable_ = nullptr;     // HTTPS parsed results table.
    QPlainTextEdit* httpsProxyLogOutput_ = nullptr;// HTTPS proxy log output box.
    std::vector<ks::network::HttpsProxyParsedEntry> httpsParsedEntryCache_; // HTTPS parsing result cache, one-to-one correspondence with row numbers and table entries.

    // ========================= Tab10: hosts file editor ====================
    QWidget* hostsFileEditorPage_ = nullptr;       // hosts file editor page container.
    QVBoxLayout* hostsFileEditorLayout_ = nullptr; // hosts file editor page layout.
    CodeEditorWidget* hostsFileEditor_ = nullptr;  // hosts file editor (full-screen reuse of project text editing component).

    // ======================= Background Services and Cache ========================
    std::unique_ptr<ks::network::TrafficMonitorService> trafficService_; // Background service for packet capture and rate limiting.
    ks::network::NidsEngine nidsEngine_; // NIDS rule engine instance.
    QTimer* rateLimitRefreshTimer_ = nullptr; // Rate-limit rule polling refresh timer.
    QTimer* packetFlushTimer_ = nullptr;      // Packet batch flush timer (critical for UI throttling).
    QTimer* r0TrafficRefreshTimer_ = nullptr; // R0 WFP per-packet incremental query polling timer.
    QTimer* connectionRefreshTimer_ = nullptr; // Connection snapshot polling refresh timer (TCP/UDP).
    QTimer* multiDownloadRefreshTimer_ = nullptr; // Multi-threaded download page refresh timer (progress UI throttling).
    std::unique_ptr<ks::network::HttpsMitmProxyService> httpsProxyService_; // HTTPS MITM proxy service object.
    bool monitorRunning_ = false;             // Packet capture running status cache.
    enum class TrafficMonitorSource : std::uint8_t
    {
        kStopped = 0, // Currently not monitoring.
        kStarting,    // Detecting R0 capabilities.
        kR0,          // Uses the driver WFP IPv4/IPv6 per-packet recording.
        kR3           // Use the original user-mode packet capture.
    };
    TrafficMonitorSource monitorSource_ = TrafficMonitorSource::kStopped; // Current explicit data source.
    bool httpsProxyRunning_ = false;          // HTTPS proxy running state cache.
    bool httpsProxyServiceInitialized_ = false; // Whether the HTTPS proxy service has been deferred initialized.
    bool httpsSystemProxySnapshotCaptured_ = false; // Whether the proxy configuration before this page was modified has been saved.
    bool httpsProxyRecoveryRequired_ = false; // Whether there are persistent proxy transactions that have not been successfully recovered or cleared.
    std::optional<std::uint32_t> httpsPreviousProxyEnable_; // Original ProxyEnable; default indicates the original value does not exist.
    std::optional<std::uint32_t> httpsPreviousAutoDetect_;  // Original AutoDetect; default indicates the original value does not exist.
    std::optional<QString> httpsPreviousProxyServer_;       // Original ProxyServer; default indicates the original value does not exist.
    std::optional<QString> httpsPreviousProxyOverride_;     // Original ProxyOverride; default indicates the original value does not exist.
    std::optional<QString> httpsPreviousAutoConfigUrl_;     // Original AutoConfigURL; default indicates the original value does not exist.
    std::atomic_bool monitorStopInProgress_{ false }; // Indicates the stop process is in progress to avoid UI jitter from duplicate stop calls.
    std::atomic_bool r0TrafficRefreshPending_{ false }; // R0 per-packet query re-entry gate.
    std::atomic<std::uint64_t> monitorGeneration_{ 0 }; // Generation counter for start/stop; discard expired async results.
    std::unique_ptr<std::thread> monitorStopThread_;  // Join thread for asynchronous stop to prevent main thread blocking.

    // Current applied filter status:
    // - m_monitorFilterRuleGroupUiList stores 'original UI configuration'.
    // - m_activeMonitorFilterGroupList stores 'compilable match conditions'.
    // - m_monitorProcessCandidateList is a PID input completion cache.
    std::vector<std::unique_ptr<MonitorFilterRuleGroupUiState>> monitorFilterRuleGroupUiList_;
    std::vector<MonitorFilterRuleGroupCompiled> activeMonitorFilterGroupList_;
    std::vector<MonitorProcessCandidate> monitorProcessCandidateList_;
    int monitorFilterNextGroupId_ = 1;
    qint64 monitorProcessCandidateLastRefreshMs_ = 0;

    static constexpr std::size_t kMaxPacketCacheCount = 6000;          // Packet cache limit.
    // Maximum limit for the background refresh queue:
    // - Increase the capacity to 80000 to reduce packet loss from queue overflow when UI refresh cannot keep up with traffic bursts;
    // - Retains a hard limit to prevent memory out-of-control in extreme scenarios.
    static constexpr std::size_t kMaxPendingPacketQueueCount = 80000;
    std::deque<std::uint64_t> packetSequenceOrder_; // Packet sequence numbers cached in chronological order.
    std::unordered_map<std::uint64_t, ks::network::PacketRecord> packetBySequence_; // Sequence number -> packet mapping.
    std::uint64_t r0LastEventSequence_ = 0; // Consumed driver WFP per-packet cursor, used for strict incremental deduplication.
    std::uint64_t r0LastDroppedEventCount_ = 0; // Accumulated packet-ring overwrite count for status bar display.
    std::uint64_t r0SyntheticSequence_ = (1ULL << 63U); // UI primary key index; the original driver sequence is stored separately in PacketRecord.
    QHash<QString, QString> remoteDomainCache_; // IP to domain name cache; empty resolution results are stored as "-".
    QSet<QString> remoteDomainResolutionPending_; // Remote IPs currently undergoing asynchronous resolution.
    std::vector<ProcessTraceTimelineEventPoint> packetTimelineEventPoints_; // Packet timeline drawing point cache.
    std::vector<PacketTimelineCaptureSession> packetTimelineSessionList_; // List of active monitoring sessions, used to exclude downtime intervals.
    std::unordered_map<std::uint64_t, std::uint64_t> packetTimelineTimeBySequence_; // Packet sequence number -> compressed timeline time.
    std::unordered_map<std::uint64_t, PacketTimelineRateBucket> packetTimelineRateBucketBySecond_; // Second N -> upload/download rate bucket.
    std::uint64_t packetTimelineRangeStart100ns_ = 0; // Timeline left boundary, fixed to 0 (compressed monitoring duration).
    std::uint64_t packetTimelineRangeEnd100ns_ = 0;   // Right boundary of the timeline; compressed cumulative monitoring duration.
    std::uint64_t packetTimelineSelectionStart100ns_ = 0; // The user-selected start point for the box selection, in units of 100ns.
    std::uint64_t packetTimelineSelectionEnd100ns_ = 0;   // The user-selected end point for the box selection, in units of 100ns.
    std::uint64_t packetTimelineAccumulatedActive100ns_ = 0; // Accumulated session monitoring duration completed; does not increase during shutdown.
    std::uint64_t packetTimelineLastHeartbeatSecond_ = 0; // Idle timeline refresh second counter, used to pad zero rates during empty traffic.
    qint64 lastPacketTimelineRefreshMs_ = 0; // timestamp of the last full point set copy to the timeline control, used to limit high-frequency full copies.
    bool packetTimelineUserSelectionActive_ = false;      // Whether the user has enabled traffic timeline selection filtering.
    bool packetTimelineSessionActive_ = false;            // Whether a running timeline monitoring session exists.

    // Packet buffer queue from background thread to UI thread (stores data only, does not touch UI controls).
    std::deque<ks::network::PacketRecord> pendingPacketQueue_;
    mutable std::mutex pendingPacketMutex_;
    std::uint64_t droppedPacketCount_ = 0; // Dropped packet count when the queue is full (used for status indication).

    static constexpr std::size_t kMaxNidsAlertCount = 2000; // NIDS alert cache upper limit.
    std::deque<ks::network::NidsAlert> nidsAlertList_; // NIDS alert cache, saved in chronological order.
    std::uint64_t nidsAnalyzedPacketCount_ = 0; // Number of packets sent to NIDS.
    std::uint64_t nidsTotalAlertCount_ = 0;     // Cumulative alert count for this round.

    // Connection snapshot cache:
    // - UI table rows and snapshot vectors correspond by the same index;
    // - Operations such as terminating connections or copying rows are resolved via the current row index.
    std::vector<ks::network::TcpConnectionRecord> tcpConnectionCache_;
    std::vector<ks::network::UdpEndpointRecord> udpEndpointCache_;
    std::atomic_bool connectionRefreshPending_{ false }; // Whether a connection snapshot is being enumerated in the background; prevents overlapping slow enumerations.

    // PID icon cache: avoid re-parsing EXE icons to prevent UI lag.
    QHash<quint32, QIcon> processIconCacheByPid_;

    // AliveScanTaskState: Allows background scans to safely record exit status outside the QWidget lifecycle.
    struct AliveScanTaskState
    {
        std::mutex mutex; // mutex: Protects activeTaskCount.
        std::condition_variable completion; // completion: Wakes the destructor path when the last coordinated task exits.
        std::atomic_bool cancelRequested{ false }; // cancelRequested: Cancellation request independent of QWidget.
        std::size_t activeTaskCount = 0; // activeTaskCount: number of ICMP scan coordination tasks that have not yet exited.
    };

    // Alive host scan status: prevents duplicate starts and supports user interruption.
    std::atomic_bool aliveScanRunning_{ false };
    std::atomic_bool aliveScanCancel_{ false };
    int aliveScanProgressPid_ = 0;
    QThreadPool aliveScanThreadPool_; // m_aliveScanThreadPool: Handles only the scan coordination tasks for this Dock to avoid waiting on the global task pool.
    std::shared_ptr<AliveScanTaskState> aliveScanTaskState_ = std::make_shared<AliveScanTaskState>();

    // Multi-threaded download task runtime state: supports parallel multi-task execution and periodic UI refresh.
    mutable std::mutex multiDownloadTaskMutex_; // m_multiDownloadTaskMutex: Concurrency access lock for the download task list.
    std::vector<std::shared_ptr<MultiThreadDownloadTaskState>> multiDownloadTaskList_; // m_multiDownloadTaskList: Download task state collection.
    int multiDownloadNextTaskId_ = 1; // m_multiDownloadNextTaskId: New task ID incrementing counter.
    int multiDownloadSelectedTaskId_ = 0; // m_multiDownloadSelectedTaskId: The task ID bound to the current segment details panel.
    bool multiDownloadAutoCaptureClipboardEnabled_ = true; // m_multiDownloadAutoCaptureClipboardEnabled: Whether to enable automatic clipboard capture.
    QStringList multiDownloadCaptureSuffixList_; // m_multiDownloadCaptureSuffixList: Set of suffixes currently used to identify download links.
    QString multiDownloadLastClipboardText_; // m_multiDownloadLastClipboardText: The most recently processed clipboard text (deduplicated).
    QPointer<QDialog> multiDownloadClipboardPromptDialog_; // m_multiDownloadClipboardPromptDialog: Weak reference to the current non-blocking download prompt dialog.
};

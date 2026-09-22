#pragma once

// ============================================================
// NetworkAuditPage.h
// Purpose:
// 1) Provide a network audit page to centrally display TCP/UDP cross-view, AFD, WFP, NDIS, and NSI summaries;
// 2) Merge refresh, filtering, copy, process actions, scanning, and termination actions from the original 'Connection Management' page into the TCP/UDP cross-view.
// 3) All other audit partitions remain read-only; disable, detach, and bypass actions are not provided.
// ============================================================

#include "../Framework.h"
#include "../../../shared/platform/network/NetworkConnectionTools.h"

#include <QHash>
#include <QIcon>
#include <QWidget>
#include <QJsonValue>
#include <QSet>

#include <atomic> // std::atomic_bool: Prevent concurrent refresh reentrancy.
#include <functional> // std::function: Passes the process action callback from the original connection management page to NetworkDock.
#include <memory> // std::unique_ptr: manages the asynchronous snapshot object.
#include <vector> // std::vector: Batch snapshot row cache.

class QImage;
class QLabel;
class QLineEdit;
class QPoint;
class QPushButton;
class QSplitter;
class QTabWidget;
class QTableWidget;
class QTableWidgetItem;
class QTimer;
class QVBoxLayout;
class QHBoxLayout;
struct NetworkAuditAsyncState;

class NetworkAuditPage final : public QWidget
{
public:
    // ProcessActionHandler：
    // - Input: Cross-View current row PID;
    // - Processing: Inject the existing implementation for 'Track Process/Open Process Details' from NetworkDock.
    // - Returns: Nothing.
    using ProcessActionHandler = std::function<void(std::uint32_t)>;
    using UdpEndpointBlockRuleHandler = std::function<void(std::uint32_t, const QString&)>;

    // Constructor:
    // - Input parent: Qt parent control, may be null;
    // - Processing: Build read-only audit page UI; trigger initial asynchronous refresh when the page is first displayed.
    // - Returns: Nothing.
    explicit NetworkAuditPage(QWidget* parent = nullptr);

    // Destructor:
    // - Processing: First revoke the async worker's owner, then let Qt release child controls.
    // - Returns: Nothing.
    ~NetworkAuditPage() override;

    // requestInitialRefresh:
    // - Trigger the initial read-only audit when the page first becomes active;
    // - Repeated calls do not trigger concurrent tasks.
    // - No return value.
    void requestInitialRefresh();

    // focusProcessIds:
    // - Merges the 'Jump by Process' capability from the original connection management page.
    // - Passing an empty set clears the filter and switches to TCP/UDP Cross-View.
    // - Returns: Nothing.
    void focusProcessIds(const QSet<quint32>& processIds);

    // activateCrossView:
    // - Switch to TCP/UDP Cross-View.
    // - Reusable by the network sub-page in the process details view.
    // - Returns: Nothing.
    void activateCrossView();

    // setTrackProcessHandler:
    // - Merges the original connection management page's 'Track this process' action;
    // - When handler is null, the right-click menu disables that action;
    // - Returns: Nothing.
    void setTrackProcessHandler(ProcessActionHandler handler);

    // setOpenProcessDetailHandler:
    // - Merge the 'Go to Process Details' action from the original connection management page.
    // - When handler is null, the right-click menu disables that action;
    // - Returns: Nothing.
    void setOpenProcessDetailHandler(ProcessActionHandler handler);

    // setUdpEndpointBlockRuleHandler：
    // - Purpose: Injects a pre-fill action from NetworkDock mapping 'NSI UDP endpoint' to 'firewall block rule'.
    // - UDP menu hides this write operation when handler is null.
    void setUdpEndpointBlockRuleHandler(UdpEndpointBlockRuleHandler handler);

private:
    // CrossViewRow: Aggregated result row for the TCP/UDP cross-view.
    struct CrossViewRow
    {
        std::uint32_t processId = 0;
        QString processName;
        std::uint32_t tcpCount = 0;
        std::uint32_t udpCount = 0;
        QString tcpSummary;
        QString udpSummary;
    };

    // TcpEndpointRow: A row in the TCP detail table, merging the R3 connection table with the R0 endpoint audit row.
    struct TcpEndpointRow
    {
        std::uint32_t processId = 0; // processId: PID of the connection owner; 0 if unknown.
        QString processName;         // processName: R3 process name or R0 PID hint.
        QString localEndpointText;   // localEndpointText: Local IP:Port.
        QString remoteEndpointText;  // remoteEndpointText: Remote IP:Port.
        QString stateText;           // stateText: TCP or protocol state.
        QString detailText;          // detailText: Copyable details such as source, object address, and field mask.
        bool isR0Snapshot = false;    // isR0Snapshot: true indicates a driver read-only snapshot row.
        bool canTerminate = false;    // canTerminate: Only R3 IPv4 active connections allow DELETE_TCB.
        ks::network::TcpConnectionRecord connectionRecord; // connectionRecord: The original four-tuple used for the termination action.
    };

    // UdpEndpointRow: a row in the UDP detail table, displaying local endpoints and source diagnostics.
    struct UdpEndpointRow
    {
        std::uint32_t processId = 0; // processId: PID of the endpoint owner; 0 if unknown.
        QString processName;         // processName: R3 process name or R0 PID hint.
        QString localEndpointText;   // localEndpointText: Local IP:Port.
        QString sourceText;          // sourceText: Data source for R3/R0.
        QString detailText;          // detailText: Copyable details such as object addresses and field masks.
    };

    // AfdHandleRow: A single row of display results for an AFD-associated handle.
    struct AfdHandleRow
    {
        std::uint32_t processId = 0;
        QString processName;
        QString handleValueText;
        QString typeName;
        QString objectName;
        QString sourceText;
        QString diffText;
        QString accessText;
        QString detailText;
    };

    // WfpProviderRow: WFP provider row display result.
    struct WfpProviderRow
    {
        QString nameText;
        QString descriptionText;
        QString guidText;
        QString flagsText;
        QString serviceNameText;
        QString dataSizeText;
    };

    // WfpSubLayerRow: WFP sublayer row display result.
    struct WfpSubLayerRow
    {
        QString nameText;
        QString descriptionText;
        QString guidText;
        QString flagsText;
        QString providerGuidText;
        QString weightText;
    };

    // WfpCalloutRow: displays one WFP callout row.
    struct WfpCalloutRow
    {
        QString nameText;
        QString descriptionText;
        QString guidText;
        QString flagsText;
        QString providerGuidText;
        QString layerGuidText;
        QString calloutIdText;
    };

    // WfpFilterRow: Display result for a single WFP filter row.
    struct WfpFilterRow
    {
        QString nameText;
        QString descriptionText;
        QString guidText;
        QString flagsText;
        QString providerGuidText;
        QString layerGuidText;
        QString subLayerGuidText;
        QString weightText;
        QString actionText;
        QString conditionText;
        QString filterIdText;
    };

    // NdisAdapterRow: Displays one row of NDIS miniport/adapter results.
    struct NdisAdapterRow
    {
        QString nameText;
        QString descriptionText;
        QString ifIndexText;
        QString statusText;
        QString macText;
        QString linkSpeedText;
        QString connectionStateText;
    };

    // NdisBindingRow: Display result for one NDIS binding row.
    struct NdisBindingRow
    {
        QString adapterNameText;
        QString displayNameText;
        QString componentIdText;
        QString enabledText;
        QString instanceIdText;
    };

    // NdisProtocolRow: One-line display result for NDIS protocol / interface.
    struct NdisProtocolRow
    {
        QString interfaceAliasText;
        QString ifIndexText;
        QString addressFamilyText;
        QString connectionStateText;
        QString interfaceMetricText;
        QString mtuText;
    };

    // NdisUnknownRow: fallback evidence retained when the driver cannot prove specific NDIS object boundaries.
    // These rows must not be projected into any of Miniport, Filter, Protocol, or Binding.
    struct NdisUnknownRow
    {
        QString kindText;
        QString componentText;
        QString ownerModuleText;
        QString objectAddressText;
        QString detailText;
    };

    // NsiSummaryRow: A single row of NSI summary display results.
    struct NsiSummaryRow
    {
        QString metricText;
        QString valueText;
    };

    // R0NetworkSummaryRow: A summary row for the R0 network audit wrapper.
    // Input: populated after buildAuditSnapshot calls ArkDriverClient.
    // Handling: The UI displays only ok/unsupported/unavailable status, counts, truncation, and messages.
    // Return: The struct has no function return; refreshNsiSummaryTable converts it into a table row.
    struct R0NetworkSummaryRow
    {
        QString nameText;
        QString statusText;
        QString countText;
        QString truncatedText;
        QString messageText;
    };

    // AuditSnapshot: All read-only audit snapshots required for one refresh.
    struct AuditSnapshot
    {
        std::vector<TcpEndpointRow> tcpEndpointRows;
        std::vector<UdpEndpointRow> udpEndpointRows;
        std::vector<CrossViewRow> crossViewRows;
        std::vector<AfdHandleRow> afdRows;
        std::vector<WfpProviderRow> wfpProviderRows;
        std::vector<WfpSubLayerRow> wfpSubLayerRows;
        std::vector<WfpCalloutRow> wfpCalloutRows;
        std::vector<WfpFilterRow> wfpFilterRows;
        std::vector<NdisAdapterRow> ndisAdapterRows;
        std::vector<NdisBindingRow> ndisBindingRows;
        std::vector<NdisProtocolRow> ndisProtocolRows;
        std::vector<NdisUnknownRow> ndisUnknownRows;
        std::vector<NsiSummaryRow> nsiSummaryRows;
        std::vector<R0NetworkSummaryRow> r0SummaryRows;
        QString r0TcpStatusText;
        QString r0UdpStatusText;
        QString statusText;
        QString detailText;
    };

    // initializeUi:
    // - Build the top control bar and four audit sections.
    // - Inputs: None;
    // - Returns: Nothing.
    void initializeUi();

    // initializeConnections:
    // - Connection refresh button and table interaction;
    // - Inputs: None;
    // - Returns: Nothing.
    void initializeConnections();

    // refreshAllSnapshotsAsync:
    // - Background one-time collection of all read-only audit snapshots.
    // - forceRefresh indicates a user-initiated refresh;
    // - Return: None. Results are posted back to the UI thread.
    void refreshAllSnapshotsAsync(bool forceRefresh);

    // refreshCrossViewAsync:
    // - The original connection management page's 2.2-second auto-refresh only enumerates R3 TCP/UDP;
    // - Retain the R0 rows obtained from the most recent complete audit to avoid repeated collection of AFD/WFP/NDIS;
    // - Returns: Nothing.
    void refreshCrossViewAsync();

    // applySnapshot:
    // - Write all completed background snapshots back to the respective tables.
    // - Input snapshot: Results collected by the background thread;
    // - Returns: Nothing.
    void applySnapshot(const AuditSnapshot& snapshot);

    // refreshCrossViewTable:
    // - Rebuild TCP/UDP detail tables and process-dimension cross-view tables.
    // - Input snapshot: Complete network snapshot from the backend;
    // - Returns: Nothing.
    void refreshCrossViewTable(const AuditSnapshot& snapshot);

    // terminateSelectedTcpConnection:
    // - Terminates the selected R3 IPv4 TCP active connection in Cross-View;
    // - R0 snapshot rows, IPv6, LISTEN, and similar cases provide an explicit reason why the operation is unavailable;
    // - Returns: Nothing.
    void terminateSelectedTcpConnection();

    // showCrossViewContextMenu:
    // - Provides copy, refresh, process tracking, process details, scan, terminate, and clear PID filter for TCP/UDP tables;
    // - Explicitly apply theme styles to the menu;
    // - Returns: Nothing.
    void showCrossViewContextMenu(QTableWidget* tableWidget, const QPoint& localPosition);

    // resolveProcessIcon:
    // - Only read the PID icon cache; never perform OpenProcess or Shell icon extraction on the main table-building path.
    // - Return a placeholder icon on cache miss and submit a background resolution task;
    // - Input processId: target process PID;
    // - Returns: cached icon or placeholder icon.
    QIcon resolveProcessIcon(std::uint32_t processId);

    // scheduleProcessIconResolution:
    // - Submit the executable path query for a given PID and shell icon extraction to the global thread pool;
    // - Deduplicate by the same PID via m_processIconPendingPidSet to avoid redundant dispatching across three tables;
    // - Input processId: target process PID;
    // - Returns: None. Must be called on the UI thread.
    void scheduleProcessIconResolution(std::uint32_t processId);

    // applyProcessIconResolutionResult:
    // - Receive icon bitmaps returned from the background thread, construct a QIcon to write to the cache, and complete the same-PID rows already in the table;
    // - Input processId: target process PID;
    // - Input iconImage: bitmap extracted in the background; a null bitmap indicates resolution failure and fallback to a placeholder icon;
    // - Returns: None. Must be called on the UI thread.
    void applyProcessIconResolutionResult(std::uint32_t processId, QImage iconImage);

    // updateCrossViewActionState:
    // - Update the button based on TCP selection and PID filter state.
    // - Returns: Nothing.
    void updateCrossViewActionState();

    // applyCrossViewSearchFilter:
    // - Real-time hide rows in the TCP, UDP, and process summary tables that do not match the current search term.
    // - The search is combined with the existing PID filter without modifying the snapshot cache or UserRole row indices.
    // - Returns: Nothing.
    void applyCrossViewSearchFilter();

    // refreshAfdTable:
    // - Rebuild AFD-related handle table;
    // - Input: snapshot - AFD handle results from the background.
    // - Returns: Nothing.
    void refreshAfdTable(const std::vector<AfdHandleRow>& snapshot);

    // refreshWfpTables:
    // - Rebuilds four read-only tables for WFP providers, sublayers, callouts, and filters.
    // - Input snapshot: WFP directory results from the background;
    // - Returns: Nothing.
    void refreshWfpTables(const AuditSnapshot& snapshot);

    // refreshNdisTables:
    // - Rebuild NDIS miniport / binding / protocol tables;
    // - Input snapshot: NDIS results from the background;
    // - Returns: Nothing.
    void refreshNdisTables(const AuditSnapshot& snapshot);

    // refreshNsiSummaryTable:
    // - Rebuild the NSI and R0 network audit summary table.
    // - Input snapshot: complete snapshot from the backend;
    // - Returns: Nothing.
    void refreshNsiSummaryTable(const AuditSnapshot& snapshot);

    // buildAuditSnapshot:
    // - Collect all read-only audit data in a background thread;
    // - Returns: Complete snapshot and status text.
    static AuditSnapshot buildAuditSnapshot(bool crossViewOnly = false);

    // runPowerShellTextSync:
    // - Executes PowerShell synchronously and returns stdout text.
    // - scriptText: The script to be executed
    // - timeoutMs is the wait timeout duration.
    // - Returns: stdout; returns diagnostic text on failure.
    static QString runPowerShellTextSync(const QString& scriptText, int timeoutMs, QString* errorTextOut = nullptr);

    // createCell:
    // - Create a unified read-only table cell.
    // - Input cellText: Cell text;
    // - Returns: An item ready to be written directly into the table.
    static QTableWidgetItem* createCell(const QString& cellText);

    // guidToText:
    // - Formats a GUID into a human-readable string.
    // - Input guid: Windows GUID;
    // - Returns: Stringified GUID.
    static QString guidToText(const GUID& guid);

    // bytesToHexText:
    // - Formats a byte count into hexadecimal display.
    // - Input: value, the numeric value to format.
    // - Returns: a hexadecimal string.
    static QString bytesToHexText(std::uint64_t value);

    // objectToText:
    // - Convert PowerShell JSON values to stable text.
    // - Input value: JSON value;
    // - Returns: Stable display text.
    static QString objectToText(const QJsonValue& value);

    // compareContainsAfd:
    // - Check if the object name belongs to AFD-related objects.
    // - Input objectNameText: object name;
    // - Returns: true indicates a match with AFD.
    static bool compareContainsAfd(const QString& objectNameText);

    // top-level tabs / controls.
    QVBoxLayout* rootLayout_ = nullptr;
    QHBoxLayout* headerLayout_ = nullptr;
    QPushButton* refreshButton_ = nullptr;
    QLabel* statusLabel_ = nullptr;
    QTabWidget* sectionTabWidget_ = nullptr;

    // TCP / UDP cross-view.
    QWidget* crossViewPage_ = nullptr;
    QSplitter* crossViewSplitter_ = nullptr;
    QSplitter* crossViewTopSplitter_ = nullptr;
    QHBoxLayout* crossControlLayout_ = nullptr;
    QLineEdit* crossSearchEdit_ = nullptr;        // m_crossSearchEdit: Real-time text filtering across three tables in Cross-View.
    QPushButton* crossAutoRefreshButton_ = nullptr;
    QPushButton* crossTerminateButton_ = nullptr;
    QPushButton* clearProcessFilterButton_ = nullptr;
    QLabel* crossFilterLabel_ = nullptr;
    QTableWidget* tcpTable_ = nullptr;
    QTableWidget* udpTable_ = nullptr;
    QTableWidget* crossSummaryTable_ = nullptr;

    // AFD view.
    QWidget* afdPage_ = nullptr;
    QTableWidget* afdTable_ = nullptr;

    // WFP view.
    QWidget* wfpPage_ = nullptr;
    QTabWidget* wfpTabWidget_ = nullptr;
    QTableWidget* wfpProviderTable_ = nullptr;
    QTableWidget* wfpSubLayerTable_ = nullptr;
    QTableWidget* wfpCalloutTable_ = nullptr;
    QTableWidget* wfpFilterTable_ = nullptr;

    // NDIS view.
    QWidget* ndisPage_ = nullptr;
    QTabWidget* ndisTabWidget_ = nullptr;
    QTableWidget* ndisAdapterTable_ = nullptr;
    QTableWidget* ndisBindingTable_ = nullptr;
    QTableWidget* ndisProtocolTable_ = nullptr;
    QTableWidget* ndisUnknownTable_ = nullptr;

    // NSI summary.
    QWidget* nsiPage_ = nullptr;
    QTableWidget* nsiSummaryTable_ = nullptr;

    QTimer* crossAutoRefreshTimer_ = nullptr; // Auto-refresh capability of the original connection management page.
    QSet<quint32> processFilterSet_; // Independent PID filter brought in from the process page.
    std::vector<TcpEndpointRow> tcpEndpointCache_; // UI rows query termination parameters via UserRole.
    std::vector<UdpEndpointRow> udpEndpointCache_; // Most recent UDP snapshot, retaining R0 rows for use.
    QString r0TcpStatusText_; // Protocol status of the most recent complete R0 TCP query; do not misreport zero rows as success.
    QString r0UdpStatusText_; // Protocol status of the most recent complete R0 UDP query.
    QHash<quint32, QIcon> processIconCache_; // PID -> Real process icon cache.
    QSet<quint32> processIconPendingPidSet_; // PIDs for icons being resolved in the background to avoid duplicate dispatches.
    ProcessActionHandler trackProcessHandler_; // Implementation of the 'Track this process' feature on the original connection page.
    ProcessActionHandler openProcessDetailHandler_; // Original implementation of the 'Go to Process Details' action on the connection page.
    UdpEndpointBlockRuleHandler udpEndpointBlockRuleHandler_; // Pre-fill for future NSI UDP endpoint traffic blocking.
    std::shared_ptr<NetworkAuditAsyncState> asyncState_; // Cross-thread back-injection of shared state; clear the owner before destruction.
    std::atomic_bool refreshInProgress_{ false };
    std::atomic_bool initialRefreshRequested_{ false };
};

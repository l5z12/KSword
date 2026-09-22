#pragma once

// ============================================================
// NetworkFirewallPage.h
// Purpose:
// 1) Provides a WFP firewall event page in the style of System Informer;
// 2) Provide Windows Firewall rule management (enumerate / add / edit / enable-disable / delete);
// 3) Dynamically load fwpuclnt.dll to avoid a strong project-link dependency on Fwpuclnt.lib.
// ============================================================

#include "../Framework.h"

#include <QWidget>

#include <atomic> // std::atomic_bool: Prevent concurrent historical refresh.
#include <cstdint> // std::uint32_t/std::uint64_t: Audit process identity field.
#include <deque>  // std::deque: real-time event queue with a fixed upper limit, evicting the oldest item in O(1).
#include <mutex>  // std::mutex: Protect real-time callback queue.
#include <thread> // std::thread: waitable history/rule refresh thread.
#include <vector> // std::vector: Batch event re-injection.

class QCheckBox;
class QLabel;
class QLineEdit;
class QPoint;
class QPushButton;
class QTabWidget;
class QTableWidget;
class QTimer;
class QVBoxLayout;
class QSplitter;
class CodeEditorWidget;

// NetworkFirewallPage:
// - Input: Qt parent control;
// - Handling: initialize the firewall events and rule management page, and start WFP history enumeration/real-time subscription as needed.
// - Return behavior: No business return value; events are rendered directly to the table.
class NetworkFirewallPage final : public QWidget
{
    Q_OBJECT

public:
    // Constructor:
    // - parent: Qt parent control;
    // - Processing: Create the UI; trigger the initial history and rule refresh when the page is displayed for the first time;
    // - Returns: Nothing.
    explicit NetworkFirewallPage(QWidget* parent = nullptr);

    // Destructor:
    // - Handling: Stop real-time subscription, close the BFE engine, and release fwpuclnt.dll.
    // - Returns: Nothing.
    ~NetworkFirewallPage() override;

    // requestInitialRefresh:
    // - Start refreshing historical events and rule snapshots when the page first becomes active.
    // - Repeated calls do not trigger concurrent tasks.
    // - No return value.
    void requestInitialRefresh();

    // addBlockRuleFromEvidence：
    // - Purpose: Pre-fills a block rule using audit evidence, which is still written to the system only after user confirmation in the editor.
    void addBlockRuleFromEvidence(
        const QString& remoteAddress,
        const QString& remotePort,
        const QString& protocolText,
        const QString& directionText,
        const QString& sourceText,
        std::uint32_t observedProcessId = 0,
        std::uint64_t expectedProcessCreationTime100ns = 0,
        const QString& expectedProcessImagePath = QString(),
        const QString& applicationPathHint = QString());

    // addUdpEndpointBlockRuleFromEvidence：
    // - Purpose: Pre-fill NSI UDP local endpoints as rules to block future traffic;
    // - Note: UDP endpoints themselves do not carry inbound/outbound semantics; they default to Outbound and must be confirmed or modified by the user in the editor.
    void addUdpEndpointBlockRuleFromEvidence(
        const QString& localEndpointText,
        std::uint32_t observedProcessId = 0);

    // FirewallEventEntry：
    // - Purpose: Save display fields for a single WFP net event.
    // - Processing logic: WFP thread fills, UI thread inserts into the table.
    // - Return behavior: Pure data structure, no function return.
    struct FirewallEventEntry
    {
        QString nameText;          // nameText: Process/application name or event name.
        QString applicationPathText;// applicationPathText: the original application path for the WFP appId, used only for pre-filling.
        QString actionText;        // actionText: Actions such as DROP/Allowed.
        QString directionText;     // directionText：In/Out/FWD/BI。
        QString ruleText;          // ruleText: Filter/rule name.
        QString descriptionText;   // descriptionText: Filter description or event description.
        QString localAddressText;  // localAddressText: Local address.
        QString localPortText;     // localPortText: Local port.
        QString localHostText;     // localHostText: Local host name.
        QString remoteAddressText; // remoteAddressText: Remote address.
        QString remotePortText;    // remotePortText: Remote port.
        QString remoteHostText;    // remoteHostText: Remote host name.
        QString protocolText;      // protocolText: TCP/UDP/ICMP or protocol number.
        QString timestampText;     // timestampText: Event timestamp.
        bool isDrop = false;       // isDrop: Whether it is a DROP action; for filtering only, does not change normal text color.
    };

    // FirewallRuleEntry：
    // - Purpose: Store display fields and original control fields for a Windows Firewall rule entry;
    // - Processing logic: background COM enumeration fills data; UI thread writes to the rule table or edit dialog.
    // - Return behavior: Pure data structure, no function return.
    struct FirewallRuleEntry
    {
        QString fingerprintText;      // fingerprintText: the matching key for the current snapshot, used for update/start-stop localization.
        QString nameText;             // nameText: Rule name.
        QString descriptionText;      // descriptionText: Rule description.
        QString applicationText;      // applicationText: program path.
        QString serviceText;          // serviceText: Service name.
        QString localPortsText;       // localPortsText: Local ports.
        QString remotePortsText;      // remotePortsText: Remote ports.
        QString localAddressesText;   // localAddressesText: Local addresses.
        QString remoteAddressesText;  // remoteAddressesText: Remote addresses.
        QString groupingText;         // groupingText: Rule grouping.
        QString actionText;           // actionText: Allow/Block text.
        QString directionText;        // directionText: In/Out text.
        QString profilesText;         // profilesText: Text for Domain/Private/Public.
        QString protocolText;         // protocolText: Text for TCP/UDP/Any.
        bool enabled = false;         // enabled: Rule enabled status.
        long actionValue = 0;         // actionValue: Original NET_FW_ACTION value.
        long directionValue = 0;      // directionValue: Raw value of NET_FW_RULE_DIRECTION.
        long profilesValue = 0;       // profilesValue: NET_FW_PROFILE_TYPE2 bitmask.
        long protocolValue = 0;       // protocolValue: Original protocol value.
    };

private:

    // initializeUi:
    // - Create the status bar, event page, and rule page;
    // - No input parameters;
    // - No return value.
    void initializeUi();

    // initializeConnections:
    // - Refresh connection events, rules, edit actions, and timed consumption queue.
    // - No input parameters;
    // - No return value.
    void initializeConnections();

    // initializeEventMonitorUi:
    // - Build the 'Event Monitoring' sub-page;
    // - No input parameters;
    // - No return value.
    void initializeEventMonitorUi();

    // initializeRuleManagerUi:
    // - Build the 'Rule Management' sub-page;
    // - No input parameters;
    // - No return value.
    void initializeRuleManagerUi();

    // refreshHistoryAsync:
    // - enumerate WFP history events in the background;
    // - forceRefresh indicates a user-initiated refresh;
    // - No return value; results are pushed to the UI.
    void refreshHistoryAsync(bool forceRefresh);

    // startLiveMonitor:
    // - Starts a BFE session, enables event collection, and subscribes to real-time WFP network events.
    // - No input parameters;
    // - No return value; status is displayed in the UI.
    void startLiveMonitor();

    // stopLiveMonitor:
    // - Cancel real-time subscription and close the current engine.
    // - No input parameters;
    // - No return value.
    void stopLiveMonitor();

    // appendEventsToTable:
    // - Input: Batch events, whether to clear existing content;
    // - Processing: Write to table; DROP retains only the filter marker, with text using the normal theme color.
    // - No return value.
    void appendEventsToTable(const std::vector<FirewallEventEntry>& eventList, bool clearBeforeAppend);

    // applyFilterToRows:
    // - Hides table rows based on the search text and 'Only DROP' state.
    // - No input parameters;
    // - No return value.
    void applyFilterToRows();

    // applyFilterToRowRange: Refresh only the filter status for the specified row range to avoid repeatedly scanning the entire table during real-time appends.
    void applyFilterToRowRange(int firstRow, int rowCount);

    // flushLiveEventsToUi:
    // - Periodically fetch events from the live queue and append them to the UI.
    // - No input parameters;
    // - No return value.
    void flushLiveEventsToUi();

    // setStatusText:
    // - Input: status text
    // - Processing: Safely post the status label from another thread.
    // - No return value.
    void setStatusText(const QString& statusText);

    // refreshRulesAsync:
    // - enumerate Windows Firewall rules in the background.
    // - forceRefresh indicates a user-initiated refresh;
    // - No return value; results are pushed to the UI.
    void refreshRulesAsync(bool forceRefresh);

    // appendRulesToTable:
    // - Input: Batch rules, whether to clear existing content;
    // - Processing: Write rules to table;
    // - No return value.
    void appendRulesToTable(const std::vector<FirewallRuleEntry>& ruleList, bool clearBeforeAppend);

    // applyRuleFilterToRows:
    // - Hide rule rows based on the search text and 'Enabled Only' status.
    // - No input parameters;
    // - No return value.
    void applyRuleFilterToRows();

    // updateRuleActionButtons:
    // - Updates the Edit/Enable-Disable/Delete buttons based on the current rule selection state.
    // - No input parameters;
    // - No return value.
    void updateRuleActionButtons();

    // updateRuleDetailEditor:
    // - Writes the full fields of the currently selected rule to the bottom CodeEditorWidget;
    // - Show operation hints when not selected;
    // - No return value.
    void updateRuleDetailEditor();

    // showRuleContextMenu:
    // - Provide rule actions such as add, disable/enable, refresh, and delete;
    // - Explicitly apply theme styles to the menu;
    // - No return value.
    void showRuleContextMenu(const QPoint& localPosition);

    // addFirewallRule:
    // - Open the new rule dialog and add the rule to the system firewall;
    // - No input parameters;
    // - No return value.
    void addFirewallRule();

    // editSelectedFirewallRule:
    // - Edit the currently selected rule.
    // - No input parameters;
    // - No return value.
    void editSelectedFirewallRule();

    // toggleSelectedFirewallRuleEnabled:
    // - Toggle the enabled state of the currently selected rule;
    // - No input parameters;
    // - No return value.
    void toggleSelectedFirewallRuleEnabled();

    // deleteSelectedFirewallRules:
    // - Delete the currently selected one or more rules;
    // - No input parameters;
    // - No return value.
    void deleteSelectedFirewallRules();

    // selectedRuleEntry:
    // - Returns the snapshot of the first selected rule entry in the current rule table.
    // - Returns: true if found, and outputs the rule.
    bool selectedRuleEntry(FirewallRuleEntry* ruleEntryOut) const;

    // ruleNameDuplicateCount:
    // - Count the number of rules with the same name in the current snapshot.
    // - Returns: Count of rules with the same name.
    int ruleNameDuplicateCount(const QString& ruleNameText) const;

    // enumerateFirewallRulesSnapshot:
    // - enumerate the current system firewall rule snapshot in the background.
    // - Return: The rule list; on failure, returns the error via errorTextOut.
    std::vector<FirewallRuleEntry> enumerateFirewallRulesSnapshot(QString* errorTextOut) const;

    // addFirewallRuleEntryToSystem:
    // - Write a new rule to the system firewall;
    // - Returns: true on success.
    bool addFirewallRuleEntryToSystem(const FirewallRuleEntry& ruleEntry, QString* errorTextOut) const;

    // updateFirewallRuleEntryInSystem:
    // - Locates and modifies the rule based on the original fingerprint.
    // - Returns: true on success.
    bool updateFirewallRuleEntryInSystem(
        const QString& originalFingerprintText,
        const FirewallRuleEntry& updatedRuleEntry,
        QString* errorTextOut) const;

    // setFirewallRuleEnabledInSystem:
    // - Locate the rule by fingerprint and toggle its enabled state;
    // - Returns: true on success.
    bool setFirewallRuleEnabledInSystem(
        const QString& fingerprintText,
        bool enabled,
        QString* errorTextOut) const;

    // deleteFirewallRuleFromSystem:
    // - Delete a system firewall rule by rule name;
    // - Returns: true on success.
    bool deleteFirewallRuleFromSystem(const QString& ruleNameText, QString* errorTextOut) const;

    // ensureWfpApiLoaded:
    // - Dynamically load fwpuclnt.dll and resolve the required WFP functions;
    // - Returns: true if all critical functions are available.
    bool ensureWfpApiLoaded(QString* errorTextOut);

    // openWfpEngine:
    // - Input: Whether to enable event collection;
    // - Processing: Open the BFE engine and, if necessary, configure WFP network event collection.
    // - Returns: true on success and outputs the handle via engineHandleOut.
    bool openWfpEngine(bool enableCollection, void** engineHandleOut, QString* errorTextOut);

    // closeWfpEngine:
    // - Input: engine handle, whether to disable collection;
    // - Processing: Optionally disable event collection and close BFE engine;
    // - No return value.
    void closeWfpEngine(void* engineHandle, bool disableCollection);

    // enumerateHistoryWithEngine:
    // - Input: BFE engine opened;
    // - Processing: Call FwpmNetEventEnum* to retrieve historical events.
    // - Returns: the event list.
    std::vector<FirewallEventEntry> enumerateHistoryWithEngine(void* engineHandle, QString* errorTextOut);

    // convertWfpEventToEntry:
    // - Input: FWPM_NET_EVENT pointer;
    // - Processing: Extract fields such as action, direction, address, port, protocol, and rule name;
    // - Returns: displayable event.
    FirewallEventEntry convertWfpEventToEntry(const void* wfpEventPointer, void* engineHandle);

    // enqueueLiveEvent:
    // - Input: WFP live callback event;
    // - Processing: Convert and enqueue into thread-safe queue.
    // - No return value.
    void enqueueLiveEvent(const void* wfpEventPointer);

    // liveEventCallback:
    // - Input: WFP event callback context and event pointer.
    // - Processing: Forward to the current page instance.
    // - No return value.
    static void __stdcall liveEventCallback(void* context, const void* eventPointer);

private:
    QVBoxLayout* rootLayout_ = nullptr;       // m_rootLayout: Page root layout.
    QTabWidget* innerTabWidget_ = nullptr;    // m_innerTabWidget: Event monitoring / rule management sub-page.
    QLabel* statusLabel_ = nullptr;           // m_statusLabel: Status and error text.
    QWidget* eventMonitorPage_ = nullptr;     // m_eventMonitorPage: Event monitoring sub-page.
    QPushButton* refreshHistoryButton_ = nullptr; // m_refreshHistoryButton: History refresh button.
    QPushButton* startLiveButton_ = nullptr;  // m_startLiveButton: Button to start live subscription.
    QPushButton* stopLiveButton_ = nullptr;   // m_stopLiveButton: Stop live subscription.
    QPushButton* clearButton_ = nullptr;      // m_clearButton: Clear table.
    QLineEdit* searchEdit_ = nullptr;         // m_searchEdit: Search input box.
    QCheckBox* dropOnlyCheck_ = nullptr;      // m_dropOnlyCheck: Show only DROP.
    QTableWidget* eventTable_ = nullptr;      // m_eventTable: Firewall event table.
    QTimer* liveFlushTimer_ = nullptr;        // m_liveFlushTimer: Timer for real-time queue consumption.
    std::atomic_bool refreshingHistory_{ false }; // m_refreshingHistory: Mutex for history refresh.
    std::thread historyRefreshThread_;        // m_historyRefreshThread: History enumeration thread to wait for before destruction.
    std::atomic_bool liveRunning_{ false };   // m_liveRunning: Real-time monitoring status.
    std::mutex liveEventMutex_;               // m_liveEventMutex: Real-time queue lock.
    std::deque<FirewallEventEntry> liveEventQueue_; // m_liveEventQueue: A bounded real-time event queue.
    QWidget* ruleManagerPage_ = nullptr;      // m_ruleManagerPage: Sub-page for rule management.
    QPushButton* refreshRulesButton_ = nullptr; // m_refreshRulesButton: Rules refresh button.
    QPushButton* addRuleButton_ = nullptr;    // m_addRuleButton: Button to add a rule.
    QPushButton* editRuleButton_ = nullptr;   // m_editRuleButton: Edit rule button.
    QPushButton* toggleRuleButton_ = nullptr; // m_toggleRuleButton: Toggle rule button.
    QPushButton* deleteRuleButton_ = nullptr; // m_deleteRuleButton: Delete rule button.
    QLineEdit* ruleSearchEdit_ = nullptr;     // m_ruleSearchEdit: Input box for rule search.
    QCheckBox* ruleEnabledOnlyCheck_ = nullptr; // m_ruleEnabledOnlyCheck: Show only enabled rules.
    QSplitter* ruleSplitter_ = nullptr;       // m_ruleSplitter: 3:1 vertical split between rule table and details.
    QTableWidget* ruleTable_ = nullptr;       // m_ruleTable: Firewall rules table.
    CodeEditorWidget* ruleDetailEditor_ = nullptr; // m_ruleDetailEditor: Read-only editor for full rule details.
    std::atomic_bool refreshingRules_{ false }; // m_refreshingRules: Refresh rule mutex.
    std::thread ruleRefreshThread_;           // m_ruleRefreshThread: Rule enumeration thread to wait for before destruction.
    std::atomic_bool initialRefreshRequested_{ false }; // m_initialRefreshRequested: Gate for the first refresh cycle.
    std::atomic_bool shuttingDown_{ false };  // m_shuttingDown: Prevent background threads from posting to UI during destruction.
    std::vector<FirewallRuleEntry> ruleEntryList_; // m_ruleEntryList: Rule snapshot cache.
    void* fwpuclntModule_ = nullptr;          // m_fwpuclntModule: Handle to the fwpuclnt.dll module.
    void* liveEngineHandle_ = nullptr;        // m_liveEngineHandle: Handle for the real-time monitoring BFE engine.
    void* liveSubscriptionHandle_ = nullptr;  // m_liveSubscriptionHandle: Real-time subscription handle.
};

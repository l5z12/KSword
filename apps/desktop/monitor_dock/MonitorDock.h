#pragma once

// ============================================================
// MonitorDock.h
// Purpose:
// 1) Implement the "WMI / ETW" dual-side Tab for the monitoring page sidebar.
// 2) Provide WMI Provider enumeration, event class selection, subscription control, and event display.
// 3) Provides ETW Provider enumeration, parameter configuration, real-time result tables, and export capabilities.
// ============================================================

#include "ProcessTraceTimelineWidget.h"
#include "../Framework.h"

// F-05: Each process identity line in the ARK Risk Center must include a collection result (success, insufficient permissions,
// or other failure are distinct values), so we directly reuse the shared CollectionOutcome instead of creating a parallel enum.
// This header is a pure value-type header with no Qt or Win32 dependencies, preventing the analysis layer from pulling in Qt dependencies.
#include "../../../shared/evidence/EvidenceEnvelope.h"

#include <QElapsedTimer>
#include <QByteArray>
#include <QHash>
#include <QJsonObject>
#include <QRegularExpression>
#include <QStringList>
#include <QWidget>
#include "EtwFilterConfig.h"

#include <atomic>      // std::atomic_bool: Background subscription status control.
#include <condition_variable> // std::condition_variable: Wait for the ETW background archival scan to exit safely.
#include <cstdint>     // std::uint32_t: Fixed-width integers such as PIDs.
#include <deque>       // std::deque: Bounded FIFO queue for high-frequency ETW events.
#include <functional>  // std::function: Filter matching callbacks.
#include <memory>      // std::unique_ptr: Thread object management.
#include <mutex>       // std::mutex: Concurrent protection for the ETW pending flush queue.
#include <string>      // std::string: Log output and COM text bridging.
#include <thread>      // std::thread: Background thread for WMI subscriptions.
#include <unordered_map> // std::unordered_map: Field mapping cache.
#include <utility>     // std::pair: Filter field key-value mapping.
#include <vector>      // std::vector: Provider/event snapshot container.

// Qt forward declaration: reduces header file compilation dependencies.
class QCheckBox;
class QComboBox;
class QHBoxLayout;
class QLabel;
class QLineEdit;
class QListWidget;
class QListWidgetItem;
class QPlainTextEdit;
class QPushButton;
class QSortFilterProxyModel;
class QSpinBox;
class QStandardItemModel;
class QTableWidget;
class QTableWidgetItem;
class QTableView;
class QTabWidget;
class QTimer;
class QEvent;
class QScrollArea;
class QVBoxLayout;
class QGridLayout;
class QShowEvent;
class QBarSet;
class QChartView;
class QLineSeries;
class QValueAxis;
class CodeEditorWidget;
class WinAPIDock;
class ProcessTraceMonitorWidget;
class DirectKernelCallMonitorWidget;
class KernelCallbackMonitorWidget;

// COM forward declarations: avoid including many WMI headers in the header file.
struct IWbemClassObject;
struct IWbemLocator;
struct IWbemServices;
struct IEnumWbemClassObject;
struct _EVENT_RECORD;

class MonitorDock final : public QWidget
{
    Q_OBJECT

public:
    // Constructor:
    // - Purpose: initialize WMI/ETW pages, connect signals and slots, and perform the initial enumeration.
    // - Parameter parent: Qt parent widget.
    explicit MonitorDock(QWidget* parent = nullptr);

    // Destructor:
    // - Purpose: Stop background threads and timers to ensure resource release.
    ~MonitorDock() override;

    // activateMonitorTab：
    // - Purpose: Switch to the specified internal sub-page tab within the Monitor page.
    // - Call: mainWindow calls this when launching the default page or navigating to 'WinAPI / WMI / ETW / Process-oriented'.
    void activateMonitorTab(const QString& tabKey);

protected:
    // event：
    // - Purpose: Capture theme/palette changes and refresh dynamic styles;
    // - Parameter eventPointer: Qt dispatched event object;
    // - Return: true indicates the event was handled by the current control or its base class.
    bool event(QEvent* eventPointer) override;

    // showEvent：
    // - Trigger WMI/ETW Provider enumeration only on first display;
    // - Avoid launching multiple concurrent background discovery tasks during main window startup.
    void showEvent(QShowEvent* event) override;

private:
    // WmiProviderEntry：
    // - Purpose: Stores information for a single WMI Provider table row.
    struct WmiProviderEntry
    {
        QString providerName;      // Provider name.
        QString nameSpaceText;     // Namespace.
        QString clsidText;         // CLSID text.
        int eventClassCount = 0;   // Supported event class count.
        bool subscribable = false; // Whether subscribable.
    };

    // EtwProviderEntry：
    // - Purpose: Stores basic ETW Provider information.
    struct EtwProviderEntry
    {
        QString providerName;      // Provider name.
        QString providerGuidText;  // Provider GUID string.
    };

    // EtwSessionEntry：
    // - Purpose: Save a snapshot of an active ETW session in the system.
    // - Invocation: Reused when enumerating, displaying, and stopping specific ETW sessions in the ETW session bar.
    struct EtwSessionEntry
    {
        QString sessionName;
        QString modeText;
        QString bufferText;
        quint32 eventsLost = 0;
        QString logFilePath;
    };

public:
    // ========================= ETW Dual Filters ==========================
    // EtwFilterStage：
    // - Purpose: Distinguish between 'pre-filtering (no capture)' and 'post-filtering (hide display only)'.
    using EtwFilterStage = ksword::monitor::EtwFilterStage;

    // EtwStringMatchMode：
    // - Purpose: String matching mode; compiled to regular expressions for execution at the lower level.
    using EtwStringMatchMode = ksword::monitor::EtwStringMatchMode;

    // EtwFilterFieldType：
    // - Purpose: Mark the filter field value type, driver compilation, and matching strategy.
    using EtwFilterFieldType = ksword::monitor::EtwFilterFieldType;

    // EtwFilterFieldId：
    // - Purpose: Uniformly identify ETW filter fields to enable fast matching after rule compilation.
    using EtwFilterFieldId = ksword::monitor::EtwFilterFieldId;

    struct EtwFilterNumericRange
    {
        std::uint64_t minValue = 0;
        std::uint64_t maxValue = 0;
    };

    struct EtwFilterIpRange
    {
        std::uint32_t minValue = 0;
        std::uint32_t maxValue = 0;
    };

    struct EtwFilterPortRange
    {
        std::uint16_t minValue = 0;
        std::uint16_t maxValue = 0;
    };

    struct EtwFilterFieldUiState
    {
        EtwFilterFieldId fieldId = EtwFilterFieldId::kProviderName;
        QString fieldKey;
        QString fieldLabel;
        QLineEdit* inputEdit = nullptr;
    };

    struct EtwFilterCategoryCheckUiState
    {
        QString categoryText;
        QCheckBox* checkBox = nullptr;
    };

    struct EtwSimpleFilterCheckUiState
    {
        QString valueText;
        QCheckBox* checkBox = nullptr;
    };

    struct EtwSimpleFilterUiState
    {
        QWidget* panelWidget = nullptr;
        QCheckBox* enabledCheck = nullptr;
        QPushButton* clearButton = nullptr;
        QLabel* stateLabel = nullptr;
        QLineEdit* pidEdit = nullptr;
        QLineEdit* processNameEdit = nullptr;
        QLineEdit* filePathEdit = nullptr;
        QLineEdit* eventIdEdit = nullptr;
        QLineEdit* eventNameEdit = nullptr;
        QLineEdit* registryPathEdit = nullptr;
        QLineEdit* networkAddressEdit = nullptr;
        QLineEdit* networkPortEdit = nullptr;
        QLineEdit* statusEdit = nullptr;
        QLineEdit* customProviderEdit = nullptr;
        QLineEdit* customActionEdit = nullptr;
        QTimer* applyDebounceTimer = nullptr;
        std::vector<EtwSimpleFilterCheckUiState> providerCheckList;
        std::vector<EtwSimpleFilterCheckUiState> actionCheckList;
    };

    struct EtwFilterRuleGroupUiState
    {
        int groupId = 0;
        QWidget* containerWidget = nullptr;
        QLabel* titleLabel = nullptr;
        QCheckBox* enabledCheck = nullptr;
        QPushButton* removeGroupButton = nullptr;

        QComboBox* stringModeCombo = nullptr;
        QCheckBox* caseSensitiveCheck = nullptr;
        QCheckBox* invertCheck = nullptr;
        QCheckBox* detailVisibleColumnsCheck = nullptr;
        QCheckBox* detailMatchAllFieldsCheck = nullptr;

        std::vector<EtwFilterFieldUiState> fieldList;
        std::vector<EtwFilterCategoryCheckUiState> categoryCheckList;
    };

    // EtwSimpleFilterModel：
    // - Purpose: Decouples simple filter input from Qt controls.
    // - Perform parsing and compilation in a temporary model during import to avoid polluting the current interface with invalid configurations.
    using EtwSimpleFilterModel = ksword::monitor::EtwSimpleFilterModel;

    // EtwFilterRuleFieldModel：
    // - Purpose: Stores a field input within a detailed rule group and its stable field identity.
    using EtwFilterRuleFieldModel = ksword::monitor::EtwFilterRuleFieldModel;

    // EtwFilterRuleGroupModel：
    // - Purpose: Store a detailed filter rule group independent of controls.
    using EtwFilterRuleGroupModel = ksword::monitor::EtwFilterRuleGroupModel;

    // EtwFilterConfigModel：
    // - Purpose: Holds both pre/post simple rules and detailed rules in a single unit.
    // - This model is only submitted to the UI, runtime, and default configuration after full compilation.
    using EtwFilterConfigModel = ksword::monitor::EtwFilterConfigModel;

    struct EtwFilterRuleFieldCompiled
    {
        EtwFilterFieldId fieldId = EtwFilterFieldId::kProviderName;
        QString fieldKey;
        QString fieldLabel;
        EtwFilterFieldType fieldType = EtwFilterFieldType::kText;
        bool requiresDecodedPayload = false;
        std::vector<QRegularExpression> regexRuleList;
        std::vector<EtwFilterNumericRange> numericRangeList;
        std::vector<EtwFilterIpRange> ipRangeList;
        std::vector<EtwFilterPortRange> portRangeList;
    };

    struct EtwFilterRuleGroupCompiled
    {
        int groupId = 0;
        int displayIndex = 0;
        bool enabled = true;
        EtwStringMatchMode stringMode = EtwStringMatchMode::kRegex;
        bool caseSensitive = false;
        bool invertMatch = false;
        bool detailVisibleColumnsOnly = false;
        bool detailMatchAllFields = true;
        bool requiresDecodedPayload = false;
        std::vector<EtwFilterRuleFieldCompiled> fieldList;

        bool hasAnyCondition() const
        {
            return !fieldList.empty();
        }
    };

    struct EtwSimpleFilterCompiled
    {
        bool enabled = true;
        std::vector<EtwFilterNumericRange> pidRangeList;
        std::vector<EtwFilterNumericRange> eventIdRangeList;
        std::vector<EtwFilterIpRange> networkAddressRangeList;
        std::vector<EtwFilterPortRange> networkPortRangeList;
        QStringList providerPresetNameList;
        QStringList providerCustomTokenList;
        QStringList actionPresetList;
        QStringList actionCustomTokenList;
        QStringList processNameTokenList;
        QStringList filePathTokenList;
        QStringList eventNameTokenList;
        QStringList registryPathTokenList;
        QStringList statusTokenList;

        bool hasAnyCondition() const
        {
            return enabled
                && (!pidRangeList.empty()
                    || !eventIdRangeList.empty()
                    || !networkAddressRangeList.empty()
                    || !networkPortRangeList.empty()
                    || !providerPresetNameList.empty()
                    || !providerCustomTokenList.empty()
                    || !actionPresetList.empty()
                    || !actionCustomTokenList.empty()
                    || !processNameTokenList.empty()
                    || !filePathTokenList.empty()
                    || !eventNameTokenList.empty()
                    || !registryPathTokenList.empty()
                    || !statusTokenList.empty());
        }

        bool requiresDecodedPayload() const
        {
            return hasAnyCondition()
                && (!pidRangeList.empty()
                    || !networkAddressRangeList.empty()
                    || !networkPortRangeList.empty()
                    || !actionPresetList.empty()
                    || !actionCustomTokenList.empty()
                    || !processNameTokenList.empty()
                    || !filePathTokenList.empty()
                    || !registryPathTokenList.empty()
                    || !statusTokenList.empty());
        }
    };

    struct EtwFilterStageCompiledSnapshot
    {
        EtwSimpleFilterCompiled simpleFilter;
        std::vector<EtwFilterRuleGroupCompiled> detailedGroupList;
    };

    // EtwFilterConfigCompiledModel：
    // - Purpose: Save the complete compilation results for the four paths of the temporary configuration model.
    // - The current runtime filter is replaced only if all four paths succeed.
    struct EtwFilterConfigCompiledModel
    {
        EtwSimpleFilterCompiled preSimpleFilter;     // preSimpleFilter: Compiled result of the pre-simple filter rules.
        EtwSimpleFilterCompiled postSimpleFilter;    // postSimpleFilter: The compiled result of the post-simple rule.
        std::vector<EtwFilterRuleGroupCompiled> preGroupList;  // preGroupList: Compiled results of pre-detailed rules.
        std::vector<EtwFilterRuleGroupCompiled> postGroupList; // postGroupList: Post-filter detailed rule compilation results.
    };

    struct EtwCapturedEventRow
    {
        std::uint64_t archiveSequence = 0;
        bool decodedReady = false;
        QString timestampText;
        std::uint64_t timestampValue = 0;
        QString providerName;
        QString providerGuid;
        QString providerCategory;
        int eventId = 0;
        QString eventName;
        int task = 0;
        QString taskName;
        int opcode = 0;
        QString opcodeName;
        int level = 0;
        QString levelText;
        std::uint64_t keywordMaskValue = 0;
        QString keywordMaskText;
        std::uint32_t headerPid = 0;
        std::uint32_t headerTid = 0;
        QString activityId;
        QString pidTidText;
        QString detailSummary;
        QString detailJson;
        QString detailVisibleText;
        QString detailAllText;

        QString resourceTypeText;
        QString actionText;
        QString targetText;
        QString statusText;

        std::uint32_t targetPid = 0;
        bool targetPidValid = false;
        std::uint32_t parentPid = 0;
        bool parentPidValid = false;
        std::uint32_t targetTid = 0;
        bool targetTidValid = false;

        QString processNameText;
        QString imagePathText;
        QString commandLineText;

        QString filePathText;
        QString fileOldPathText;
        QString fileNewPathText;
        QString fileOperationText;
        QString fileStatusCodeText;
        QString fileAccessMaskText;

        QString registryKeyPathText;
        QString registryValueNameText;
        QString registryHiveText;
        QString registryOperationText;
        QString registryStatusText;

        QString sourceIpText;
        std::uint32_t sourceIpValue = 0;
        bool sourceIpValid = false;
        std::uint16_t sourcePort = 0;
        bool sourcePortValid = false;
        QString destinationIpText;
        std::uint32_t destinationIpValue = 0;
        bool destinationIpValid = false;
        std::uint16_t destinationPort = 0;
        bool destinationPortValid = false;
        QString protocolText;
        QString directionText;
        QString domainText;
        QString hostText;

        QString auditResultText;
        QString userText;
        QString sidText;
        std::uint32_t securityPid = 0;
        bool securityPidValid = false;
        std::uint32_t securityTid = 0;
        bool securityTidValid = false;
        QString securityLevelText;

        QString scriptHostProcessText;
        QString scriptKeywordText;
        QString scriptTaskNameText;
        QString wmiClassNameText;
        QString wmiNamespaceText;
    };

public:
    // ArkRiskCenterEntry：
    // - Purpose: Store one aggregated result row from the ARK Risk Center.
    // - Input: Generated by read-only query aggregation from MonitorDock;
    // - Return behavior: pure data object, reusable for tables, details, and JSON/CSV exports.
    struct ArkRiskCenterEntry
    {
        QString sourceName;
        QString category;
        QString title;
        QString detail;
        QString riskScoreText;
        double riskScore = 0.0;
        QJsonObject payload;

        // ---- F-09 / F-12: Identity and evidence IDs required for navigation, fixed at the moment of collection ----

        // evidenceId: Unique evidence ID within the current snapshot.
        // Why this is mandatory: F-12 requires the navigation to carry the evidence ID; otherwise, it cannot return to the original evidence.
        // ksword::evidence::decideNavigation returns EvidenceIdMissing directly for a null ID.
        QString evidenceId;

        // identityBootId: Identifier of the collected running session.
        // Why store this with the row instead of fetching it on click: in ObjectIdentity.h, ProcessInstanceId can provide Strong
        // identity and a cross-session primary key only if bootId is nonempty and equal on both sides. Supplying the current value
        // on click would make an old cross-session snapshot falsely appear to belong to the same boot cycle as the live system.
        QString identityBootId;

        // processId: PID of the process pointed to by this row; 0 indicates this risk is unrelated to any process instance.
        std::uint32_t processId = 0U;

        // processCreateTimeKnown / processCreateTime100ns: Capture the creation time read at the moment of collection.
        // Why split into two fields? 0 is a valid time value; using 0 to represent 'unknown' would cause PID reuse
        // checks to fail silently (the two-state convention of OptionalU64 in LosslessValue.h exists for this reason).
        bool processCreateTimeKnown = false;
        std::uint64_t processCreateTime100ns = 0U;

        // processIdentityOutcome: result of identity query during the collection phase.
        // Why retain the full outcome: F-05 requires that 'Access Denied / Process Not Found / Other Failure' cannot be
        // collapsed into a single boolean; the original Win32 error code and the raw message must be preserved. The message is
        // the unlocalized source text because it is generated in a worker thread where LanguageManager calls are not allowed.
        ksword::evidence::CollectionOutcome processIdentityOutcome;
    };

    // navigateToProcessDetailFromArkRiskRow:
    // - Input: display row number of the Risk Center table (passed from the table's right-click menu);
    // - Handling: F-12 first uses ksword::evidence::decideNavigation to validate the navigation request (identity available,
    //   evidence ID present and within snapshot, target page exists, object still valid); F-09 then re-validates the process
    //   instance identity at the moment of jump using resolveProcessNavigation. Only if both checks pass is the call made.
    //   ks::ui::openProcessDetailByIdentity；
    // - Return: None. If any criterion fails, only a description is shown; never revert to a
    //   raw PID jump, as that is the entry point for opening unrelated processes after PID reuse.
    void navigateToProcessDetailFromArkRiskRow(int tableRow);

private:
    // ========================= UI Initialization =========================
    void initializeUi();
    void initializePerformancePanel();
    void initializeWmiTab();
    void initializeEtwTab();
    // initializeArkRiskCenterTab:
    // - Build a read-only ARK Risk Center tab aggregating Memory/Process/Driver/Callback/Hook detections;
    // - Provides JSON/CSV export entry points;
    // - Does not add a KernelDock page, nor provides a dangerous write button.
    void initializeArkRiskCenterTab();

    // ensureDirectKernelCallTabInitialized:
    // - Input: none; reads m_directKernelCallHostPage and m_directKernelCallWidget;
    // - Create real controls and syscall mappings only when first entering the 'Direct Kernel Call' tab.
    // - Return: None. The control is released by the Qt parent-child tree after being added to the host layout.
    void ensureDirectKernelCallTabInitialized();
    void ensureKernelCallbackTabInitialized();
    void ensureWinApiTabInitialized();

    // triggerDeferredDiscoveryForCurrentTab:
    // - Input: None. Reads the current internal tab.
    // - Handling: Trigger the initial Provider/session discovery only when the user enters the WMI/ETW page;
    // - Return: No return value; enumeration still proceeds on the background thread.
    void triggerDeferredDiscoveryForCurrentTab();
    void initializeConnections();
    // refreshArkRiskCenterAsync:
    // Asynchronously aggregate risk findings from multiple read-only ArkDriverClient queries.
    // - Sorts by riskScore and repopulates the table.
    // - Return value: None.
    void refreshArkRiskCenterAsync();
    // rebuildArkRiskCenterTable:
    // - Rebuild the ARK Risk Center table based on current filter conditions.
    // - Perform cache projection only; do not issue R0 calls again.
    // - Return value: None.
    void rebuildArkRiskCenterTable();
    // showArkRiskCenterDetailForCurrentRow:
    // - Display structured JSON and summary for the currently selected row in the Risk Center.
    // - Read only from local cache; do not access the driver.
    // - Return value: None.
    void showArkRiskCenterDetailForCurrentRow() const;
    // exportArkRiskCenterAsJson / exportArkRiskCenterAsCsv purpose:
    // - Exports the current Risk Center cache as JSON or CSV;
    // - If the cache is empty, prompt that integration is missing or no results are found.
    // - Return value: None.
    void exportArkRiskCenterAsJson() const;
    void exportArkRiskCenterAsCsv() const;
    void refreshPerformanceCharts();
    bool sampleCpuUsage(double* cpuUsageOut);
    bool sampleDiskRate(double* readBytesPerSecOut, double* writeBytesPerSecOut);
    bool sampleNetworkRate(double* rxBytesPerSecOut, double* txBytesPerSecOut);
    void appendLineSample(
        QLineSeries* series,
        QValueAxis* axisX,
        QValueAxis* axisY,
        double value);

    // ========================= WMI Features ==========================
    void refreshWmiProvidersAsync();
    void refreshWmiEventClassesAsync();
    // updateWmiSubscribePanelCompactLayout：
    // - Purpose: Dynamically collapse the height of the event class table in the 'WMI Subscription' right panel based on the current number of event classes.
    // - Call: Invoked once after initializing the subscription UI, and again after event class refresh completes.
    // - Parameters/Return: None (directly reads and updates member control sizes).
    void updateWmiSubscribePanelCompactLayout();
    void applyWmiProviderFilter();
    void startWmiSubscription();
    void stopWmiSubscription();
    void setWmiSubscriptionPaused(bool paused);
    void enqueueWmiEventRow(
        const QString& providerName,
        const QString& className,
        const QString& pidAndName,
        const QString& detailText);
    void applyWmiEventFilter();
    void clearWmiEventFilter();
    void flushWmiPendingRows();
    void appendWmiEventRow(
        const QString& providerName,
        const QString& className,
        const QString& pidAndName,
        const QString& detailText);
    void exportWmiRowsToTsv();
    void openWmiEventDetailViewerForRow(int row) const;
    void showWmiEventContextMenu(const QPoint& position);

    // ========================= ETW functionality ==========================
    void refreshEtwProvidersAsync();
    void refreshEtwSessionsAsync();
    void stopSelectedEtwSessions();
    void startEtwCapture();
    void stopEtwCapture();
    void setEtwCapturePaused(bool paused);
    void updateEtwCaptureActionState();
    // flushEtwPendingRows：
    // - Purpose: Batch flush accumulated ETW events from the background thread into the table and timeline cache;
    // - Parameter captureFinished: true indicates that the right boundary of the timeline is fixed in a stopped state after flushing.
    // - Returns: Nothing.
    void flushEtwPendingRows(bool captureFinished);
    // applyEtwTimelineSelection：
    // - Purpose: Receive the valid start and end times from the ETW timeline control after excluding pause intervals.
    // - Processing: Record valid time windows and reuse the post-filtering flow to hide table rows.
    // - Returns: Nothing.
    void applyEtwTimelineSelection(std::uint64_t start100ns, std::uint64_t end100ns);
    // etwRawTimestampToTimelineTimestamp：
    // - Purpose: Convert ETW raw absolute 100ns timestamps to timeline timestamps excluding pause intervals.
    // - Parameter rawTimestamp100ns: raw ETW timestamp for an event or range boundary.
    // - Returns: a valid timestamp that can be used by the timeline control for rendering or filtering.
    std::uint64_t etwRawTimestampToTimelineTimestamp(std::uint64_t rawTimestamp100ns) const;
    // closeEtwTimelinePauseInterval：
    // - Purpose: Fix the current paused interval as a closed interval when resuming monitoring.
    // - Parameter resumeTime100ns: Original system time at the moment of resuming monitoring.
    // - Returns: Nothing.
    void closeEtwTimelinePauseInterval(std::uint64_t resumeTime100ns);
    // refreshEtwTimelineRange：
    // - Purpose: Update the left and right boundaries of the timeline based on the ETW listener's running/paused/stopped state.
    // - Input captureFinished: true indicates the right side is fixed to the stop valid time; false indicates the right side follows the running valid time;
    // - Returns: Nothing.
    void refreshEtwTimelineRange(bool captureFinished);
    // refreshEtwTimelinePoints：
    // - Purpose: Push lightweight points of captured ETW events to the timeline for repainting.
    // - Returns: Nothing.
    void refreshEtwTimelinePoints();
    // isEtwTimelineFilterActive：
    // - Purpose: Checks whether the user has enabled time window filtering via the ETW timeline.
    // - Returns: true indicates that post-filtering requires an additional time range check.
    bool isEtwTimelineFilterActive() const;
    // prepareEtwArchiveSession: Creates the directory for the current full ETW archive and resets the 10-second segment state.
    bool prepareEtwArchiveSession(QString* errorTextOut);
    // archiveEtwCapturedRow: Write an event that has completed pre-filtering and decoding to disk for archival, then allow it to enter the UI mirror queue.
    bool archiveEtwCapturedRow(EtwCapturedEventRow* rowData);
    // finishEtwArchiveSession: Compresses pending data into blocks and seals the current segment; can be called repeatedly.
    void finishEtwArchiveSession(bool flushToPhysicalDisk = true);
    // rebuildEtwArchiveFilterAsync: Stream-scan archived segments, retaining only the most recent 6000 matching results.
    void rebuildEtwArchiveFilterAsync();
    // scheduleEtwArchiveFilterRebuild: Merges consecutive rule or timeline changes to avoid redundant concurrent archive scanning.
    void scheduleEtwArchiveFilterRebuild();
    // ETW archive scanning uses a reference-counted lifecycle; the destructor cancels and waits for background tasks to exit.
    bool beginEtwArchiveBackgroundTask();
    void endEtwArchiveBackgroundTask();
    void cancelAndWaitEtwArchiveBackgroundTasks();
    // replaceEtwRowsWithSnapshot: Replace the UI window with background filtering results; the complete archive remains on disk.
    void replaceEtwRowsWithSnapshot(
        std::deque<EtwCapturedEventRow> rows,
        std::uint64_t totalMatchCount,
        std::uint64_t scannedRowCount,
        std::uint64_t scannedMaxSequence);
    // updateEtwCollapseHeight：
    // - Purpose: Trigger recalculation of the geometry for the collapsed ETW section;
    // - Note: The current collapsed area no longer uses QToolBox, so it does not force retaining an expanded page.
    void updateEtwCollapseHeight();
    static void WINAPI etwEventRecordCallback(struct _EVENT_RECORD* eventRecordPtr);
    void enqueueEtwEventFromRecord(const struct _EVENT_RECORD* eventRecordPtr);
    void appendEtwEventRow(
        const QString& providerName,
        int eventId,
        const QString& eventName,
        std::uint32_t pidValue,
        std::uint32_t tidValue,
        const QString& detailJson,
        const QString& activityIdText);
    void exportEtwRowsToTsv(bool visibleOnly = true);
    void openEtwEventDetailViewerForRow(int row) const;
    void showEtwEventContextMenu(const QPoint& position);

    // ========================= ETW Dual Filtering ========================
    void initializeEtwFilterPanels();
    QWidget* createEtwSimpleFilterPanel(EtwFilterStage stage, QWidget* parentWidget);
    EtwSimpleFilterUiState& etwSimpleFilterUi(EtwFilterStage stage);
    const EtwSimpleFilterUiState& etwSimpleFilterUi(EtwFilterStage stage) const;
    void scheduleEtwSimpleFilterApply(EtwFilterStage stage);
    void clearEtwSimpleFilter(EtwFilterStage stage, bool applyRules = true);
    void updateEtwSimpleFilterStateLabel(EtwFilterStage stage);
    // captureEtwSimpleFilterModel / captureEtwFilterGroupModels：
    // - Purpose: Take a read-only snapshot of current control values for compilation and persistent reuse.
    EtwSimpleFilterModel captureEtwSimpleFilterModel(EtwFilterStage stage) const;
    std::vector<EtwFilterRuleGroupModel> captureEtwFilterGroupModels(EtwFilterStage stage) const;
    EtwFilterConfigModel captureEtwFilterConfigModel() const;
    // tryCompileEtwSimpleFilterModel / tryCompileEtwFilterGroupModels：
    // - Purpose: Perform all semantic validation and compilation on a temporary model without accessing Qt controls.
    bool tryCompileEtwSimpleFilterModel(
        EtwFilterStage stage,
        const EtwSimpleFilterModel& filterModel,
        EtwSimpleFilterCompiled& compiledFilterOut,
        QString& errorTextOut) const;
    bool tryCompileEtwFilterGroupModels(
        EtwFilterStage stage,
        const std::vector<EtwFilterRuleGroupModel>& groupModelList,
        std::vector<EtwFilterRuleGroupCompiled>& compiledGroupsOut,
        QString& errorTextOut) const;
    bool tryCompileEtwFilterConfigModel(
        const EtwFilterConfigModel& filterModel,
        EtwFilterConfigCompiledModel& compiledModelOut,
        QString& errorTextOut) const;
    bool tryCompileEtwSimpleFilter(
        EtwFilterStage stage,
        EtwSimpleFilterCompiled& compiledFilterOut,
        QString& errorTextOut) const;
    void addEtwFilterRuleGroup(EtwFilterStage stage);
    void removeEtwFilterRuleGroup(EtwFilterStage stage, int groupId);
    void rebuildEtwFilterRuleGroupUi(EtwFilterStage stage);
    void clearEtwFilterGroups(EtwFilterStage stage, bool resetTimelineSelection = false);
    void applyEtwFilterRules(EtwFilterStage stage);
    void applyEtwPostFilterToTable(int firstRow = 0, bool updateStateLabel = true);
    void updateEtwFilterStateLabel(EtwFilterStage stage);
    bool tryCompileEtwFilterGroups(
        EtwFilterStage stage,
        std::vector<EtwFilterRuleGroupCompiled>& compiledGroupsOut,
        QString& errorTextOut) const;
    EtwFilterRuleGroupUiState* findEtwFilterRuleGroupById(EtwFilterStage stage, int groupId);
    const EtwFilterRuleGroupUiState* findEtwFilterRuleGroupById(EtwFilterStage stage, int groupId) const;
    QString etwFilterConfigPath() const;
    // tryParseEtwFilterConfigModel：
    // - Purpose: Strictly parse supported version JSON and normalize fields and preset values in a temporary model.
    bool tryParseEtwFilterConfigModel(
        const QByteArray& jsonData,
        EtwFilterConfigModel& filterModelOut) const;
    QJsonObject serializeEtwFilterConfigModel(const EtwFilterConfigModel& filterModel) const;
    bool saveEtwFilterConfigModelToPath(
        const EtwFilterConfigModel& filterModel,
        const QString& filePath,
        bool showErrorDialog) const;
    // commitEtwFilterConfigModel：
    // - Purpose: Switch UI, runtime rules, and pre-thread snapshots all at once in the UI thread.
    void commitEtwFilterConfigModel(
        const EtwFilterConfigModel& filterModel,
        EtwFilterConfigCompiledModel compiledModel);
    bool saveEtwFilterConfigToPath(const QString& filePath, bool showErrorDialog) const;
    bool loadEtwFilterConfigFromPath(
        const QString& filePath,
        bool showErrorDialog,
        bool persistAsDefault = false);
    void saveEtwFilterConfigToDefaultPath(bool showDialog) const;
    void loadEtwFilterConfigFromDefaultPath(bool showDialog);
    void importEtwFilterConfigFromUserSelectedPath();
    void exportEtwFilterConfigToUserSelectedPath() const;

    // ========================= Stop process ==========================
    // stopWmiSubscriptionInternal：
    // - Purpose: Stop WMI subscription, optionally synchronously wait for thread exit;
    // - When waitForThread=true, used for safe destruction exit; when false, used for non-blocking UI stop.
    void stopWmiSubscriptionInternal(bool waitForThread);

    // stopEtwCaptureInternal：
    // - Purpose: Stop ETW capture, optionally synchronously wait for thread exit;
    // - When waitForThread=true, used for safe destruction exit; when false, used for non-blocking UI stop.
    void stopEtwCaptureInternal(bool waitForThread);

private:
    // ========================= Top-level Layout =========================
    QVBoxLayout* rootLayout_ = nullptr;    // Root layout.
    QWidget* perfPanel_ = nullptr;         // Top performance chart panel.
    QGridLayout* perfPanelLayout_ = nullptr; // Top performance chart layout.
    QTimer* perfUpdateTimer_ = nullptr;    // Performance chart refresh timer (default 1 second).
    QTabWidget* sideTabWidget_ = nullptr;  // Sidebar Tab container.
    ProcessTraceMonitorWidget* processTraceWidget_ = nullptr; // m_processTraceWidget: Process trace monitoring sub-page.
    QWidget* kernelCallbackHostPage_ = nullptr; // Kernel callback monitoring host page is lazily loaded.
    KernelCallbackMonitorWidget* kernelCallbackWidget_ = nullptr; // Actual kernel callback monitoring widget.
    QWidget* directKernelCallHostPage_ = nullptr; // m_directKernelCallHostPage: Host page for direct kernel calls, loaded on demand.
    DirectKernelCallMonitorWidget* directKernelCallWidget_ = nullptr; // m_directKernelCallWidget: Direct kernel call monitoring sub-page.
    QWidget* winApiPage_ = nullptr;        // m_winApiPage: Host container for the WinAPI sub-page.
    WinAPIDock* winApiWidget_ = nullptr;   // m_winApiWidget: Actual WinAPI monitoring control.
    QWidget* arkRiskCenterPage_ = nullptr;  // m_arkRiskCenterPage: Host for the ARK Risk Center page.
    QPushButton* arkRiskRefreshButton_ = nullptr; // Risk center refresh button.
    QPushButton* arkRiskExportJsonButton_ = nullptr; // Risk center JSON export button.
    QPushButton* arkRiskExportCsvButton_ = nullptr; // Risk center CSV export button.
    QLineEdit* arkRiskFilterEdit_ = nullptr; // Risk center full-field filter box.
    QCheckBox* arkRiskHighOnlyCheck_ = nullptr; // Display high-risk records only.
    QLabel* arkRiskStatusLabel_ = nullptr; // Risk center status label.
    QTableWidget* arkRiskTable_ = nullptr; // Risk center results table.
    CodeEditorWidget* arkRiskDetailEdit_ = nullptr; // Risk center detail text, using a unified read-only code editor.

    QChartView* cpuChartView_ = nullptr;      // CPU bar chart view.
    QChartView* memoryChartView_ = nullptr;   // Memory bar chart view.
    QChartView* diskChartView_ = nullptr;     // Disk line chart view.
    QChartView* networkChartView_ = nullptr;  // Network line chart view.
    QBarSet* cpuBarSet_ = nullptr;            // CPU single-bar data set.
    QBarSet* memoryBarSet_ = nullptr;         // Memory bar set.
    QLineSeries* diskReadSeries_ = nullptr;   // Disk read rate line series.
    QLineSeries* diskWriteSeries_ = nullptr;  // Disk write rate line series.
    QLineSeries* networkRxSeries_ = nullptr;  // Network download rate line series.
    QLineSeries* networkTxSeries_ = nullptr;  // Network upload rate line series.
    QValueAxis* diskAxisX_ = nullptr;         // Disk chart X-axis.
    QValueAxis* diskAxisY_ = nullptr;         // Disk chart Y-axis.
    QValueAxis* networkAxisX_ = nullptr;      // Network chart X-axis.
    QValueAxis* networkAxisY_ = nullptr;      // Network chart Y-axis.
    int perfHistoryLength_ = 60;                        // Number of points retained in the line chart.
    int perfSampleCounter_ = 0;                         // Current sample index.
    std::uint64_t lastCpuIdleTime_ = 0;                // timestamp of the last CPU idle time.
    std::uint64_t lastCpuKernelTime_ = 0;              // Last CPU kernel timestamp.
    std::uint64_t lastCpuUserTime_ = 0;                // timestamp of the last CPU user time.
    bool cpuSampleValid_ = false;                      // Whether CPU sampling has been initialized.
    std::uint64_t lastNetworkRxBytes_ = 0;             // Accumulated network bytes received in the last round.
    std::uint64_t lastNetworkTxBytes_ = 0;             // Accumulated network bytes sent in the last round.
    qint64 lastNetworkSampleMs_ = 0;                   // Last network sampling time (ms).
    void* diskPerfQueryHandle_ = nullptr;              // PDH query handle (disk performance).
    void* diskReadCounterHandle_ = nullptr;            // PDH disk read counter handle.
    void* diskWriteCounterHandle_ = nullptr;           // PDH disk write counter handle.

    // ========================= WMI Page ============================
    QWidget* wmiPage_ = nullptr;                  // WMI main page.
    QVBoxLayout* wmiLayout_ = nullptr;            // WMI page layout.
    QWidget* wmiTopConfigPanel_ = nullptr;        // WMI top collapsible panel.
    QHBoxLayout* wmiTopConfigLayout_ = nullptr;   // WMI top collapsible section horizontal layout.
    QWidget* wmiProviderPanel_ = nullptr;         // Provider panel.
    QVBoxLayout* wmiProviderPanelLayout_ = nullptr; // Provider panel layout.
    QHBoxLayout* wmiProviderControlLayout_ = nullptr; // Provider control layout.
    QLineEdit* wmiProviderFilterEdit_ = nullptr;  // Provider filter box.
    QPushButton* wmiProviderRefreshButton_ = nullptr; // Provider refresh button.
    QLabel* wmiProviderStatusLabel_ = nullptr;    // Provider status text.
    QTableView* wmiProviderTableView_ = nullptr;  // Provider table view.
    QStandardItemModel* wmiProviderModel_ = nullptr; // Provider data model.
    QSortFilterProxyModel* wmiProviderProxyModel_ = nullptr; // Provider filter model.

    QWidget* wmiSubscribePanel_ = nullptr;        // WMI subscription panel.
    QVBoxLayout* wmiSubscribeLayout_ = nullptr;   // WMI subscription layout.
    QHBoxLayout* wmiEventClassControlLayout_ = nullptr; // Event class control panel.
    QPushButton* wmiSelectAllClassesButton_ = nullptr;  // Select all button.
    QPushButton* wmiSelectNoneClassesButton_ = nullptr; // Select none button.
    QPushButton* wmiSelectWin32ClassesButton_ = nullptr; // Win32 button only.
    QTableWidget* wmiEventClassTable_ = nullptr;  // Event class selection table.
    QPlainTextEdit* wmiWhereEditor_ = nullptr;    // WHERE condition editor.
    QComboBox* wmiWhereTemplateCombo_ = nullptr;  // WHERE template dropdown.
    QHBoxLayout* wmiSubscribeControlLayout_ = nullptr; // Subscription control bar.
    QPushButton* wmiStartSubscribeButton_ = nullptr; // Start subscription button.
    QPushButton* wmiStopSubscribeButton_ = nullptr;  // Stop subscribe button.
    QPushButton* wmiPauseSubscribeButton_ = nullptr; // Pause/Resume button.
    QPushButton* wmiExportButton_ = nullptr;         // Export results button.
    QLabel* wmiSubscribeStatusLabel_ = nullptr;    // Subscribe status text.
    QLineEdit* wmiEventGlobalFilterEdit_ = nullptr; // WMI full-field filter edit.
    QLineEdit* wmiEventProviderFilterEdit_ = nullptr; // WMI Provider filter box.
    QLineEdit* wmiEventClassFilterEdit_ = nullptr; // WMI event class filter edit.
    QLineEdit* wmiEventPidFilterEdit_ = nullptr; // WMI PID/process filter input.
    QLineEdit* wmiEventDetailFilterEdit_ = nullptr; // WMI detail filter input.
    QCheckBox* wmiEventRegexCheck_ = nullptr; // WMI filter enable regex.
    QCheckBox* wmiEventCaseCheck_ = nullptr; // WMI case-sensitivity filter checkbox.
    QCheckBox* wmiEventInvertCheck_ = nullptr; // WMI filter inversion match.
    QCheckBox* wmiEventKeepBottomCheck_ = nullptr; // Whether the WMI table keeps scrolling to the bottom.
    QPushButton* wmiEventFilterClearButton_ = nullptr; // WMI filter clear button.
    QLabel* wmiEventFilterStatusLabel_ = nullptr; // WMI filter result status text.
    QTableWidget* wmiEventTable_ = nullptr;        // WMI event result table.

    std::vector<WmiProviderEntry> wmiProviders_; // Provider cache.
    std::atomic_bool wmiSubscribeRunning_{ false }; // Subscribe running state.
    std::atomic_bool wmiSubscribePaused_{ false };  // Subscribe paused state.
    std::atomic_bool wmiSubscribeStopFlag_{ false }; // Subscribe stop signal.
    std::unique_ptr<std::thread> wmiSubscribeThread_; // WMI background subscription thread.
    int wmiProviderRefreshProgressPid_ = 0;          // PID for WMI Provider refresh progress.
    int wmiSubscribeProgressPid_ = 0;                // WMI subscription progress PID.
    std::vector<QStringList> wmiPendingRows_;        // WMI event cache pending UI flush.
    std::mutex wmiPendingMutex_;                     // WMI event cache mutex.
    QTimer* wmiUiUpdateTimer_ = nullptr;             // WMI UI throttled refresh timer.

    // ========================= ETW Page ==========================
    QWidget* etwPage_ = nullptr;                    // ETW main page.
    QVBoxLayout* etwLayout_ = nullptr;              // ETW page layout.
    QWidget* etwCollapseHostWidget_ = nullptr;      // ETW independent collapse area host.
    QVBoxLayout* etwCollapseHostLayout_ = nullptr;  // ETW independent collapse area layout.
    QWidget* etwProviderPanel_ = nullptr;           // ETW Provider panel.
    QVBoxLayout* etwProviderPanelLayout_ = nullptr; // ETW Provider layout.
    QHBoxLayout* etwProviderControlLayout_ = nullptr; // ETW control bar.
    QPushButton* etwProviderRefreshButton_ = nullptr; // ETW refresh button.
    QLabel* etwProviderStatusLabel_ = nullptr;      // ETW status label.
    QWidget* etwSessionPanel_ = nullptr;            // ETW session panel.
    QVBoxLayout* etwSessionPanelLayout_ = nullptr;  // ETW session layout.
    QHBoxLayout* etwSessionControlLayout_ = nullptr; // ETW session control bar.
    QPushButton* etwSessionRefreshButton_ = nullptr; // ETW session refresh button.
    QPushButton* etwSessionStopButton_ = nullptr;   // ETW session stop button.
    QLabel* etwSessionStatusLabel_ = nullptr;       // ETW session status label.
    QTableWidget* etwSessionTable_ = nullptr;       // ETW session table.
    QComboBox* etwPresetCategoryCombo_ = nullptr;   // ETW preset template category filter combo box.
    QListWidget* etwPresetProviderList_ = nullptr;  // Checklist of common ETW preset providers.
    QListWidget* etwProviderList_ = nullptr;        // ETW Provider checkbox list.
    QLineEdit* etwManualProviderEdit_ = nullptr;    // Manual input for Provider.
    QComboBox* etwLevelCombo_ = nullptr;            // Level setting.
    QLineEdit* etwKeywordMaskEdit_ = nullptr;       // Keyword mask input.
    QSpinBox* etwBufferSizeSpin_ = nullptr;         // Buffer size input.
    QSpinBox* etwMinBufferSpin_ = nullptr;          // Input for minimum buffer count.
    QSpinBox* etwMaxBufferSpin_ = nullptr;          // Input for maximum buffer count.
    QHBoxLayout* etwCaptureControlLayout_ = nullptr; // ETW control bar layout.
    QPushButton* etwStartButton_ = nullptr;         // ETW start button.
    QPushButton* etwStopButton_ = nullptr;          // ETW stop button.
    QPushButton* etwPauseButton_ = nullptr;         // ETW pause button.
    QPushButton* etwExportButton_ = nullptr;        // ETW export button.
    QLabel* etwCaptureStatusLabel_ = nullptr;       // ETW status text.
    EtwSimpleFilterUiState etwPreSimpleFilterUi_;    // ETW simple pre-filter UI.
    EtwSimpleFilterUiState etwPostSimpleFilterUi_;   // ETW simple post-filter UI.
    QWidget* etwPreFilterPanel_ = nullptr;          // Pre-filter panel.
    QWidget* etwPostFilterPanel_ = nullptr;         // Post-filter panel.
    QVBoxLayout* etwPreFilterPanelLayout_ = nullptr; // Pre-filter layout.
    QVBoxLayout* etwPostFilterPanelLayout_ = nullptr; // Post-filter layout.
    QPushButton* etwPreFilterAddGroupButton_ = nullptr; // Pre-filter add group button.
    QPushButton* etwPreFilterApplyButton_ = nullptr; // Pre-filter apply button.
    QPushButton* etwPreFilterClearButton_ = nullptr; // Pre-filter clear button.
    QPushButton* etwPreFilterLoadDefaultButton_ = nullptr; // Button to load default configuration for pre-filtering.
    QPushButton* etwPreFilterSaveDefaultButton_ = nullptr; // Pre-filter save default configuration button.
    QPushButton* etwPreFilterImportButton_ = nullptr; // Pre-filter import configuration button.
    QPushButton* etwPreFilterExportButton_ = nullptr; // Pre-filter export configuration button.
    QLabel* etwPreFilterStateLabel_ = nullptr;      // Pre-filter status summary label.
    QScrollArea* etwPreFilterScrollArea_ = nullptr; // Pre-filter scroll area.
    QWidget* etwPreFilterGroupHostWidget_ = nullptr; // Pre-filter rule group host widget.
    QVBoxLayout* etwPreFilterGroupHostLayout_ = nullptr; // Pre-filter rule group layout.
    QPushButton* etwPostFilterAddGroupButton_ = nullptr; // Post-filter add group button.
    QPushButton* etwPostFilterApplyButton_ = nullptr; // Post-filter apply button.
    QPushButton* etwPostFilterClearButton_ = nullptr; // Post-filter clear button.
    QPushButton* etwPostFilterLoadDefaultButton_ = nullptr; // Post-filter load default configuration button.
    QPushButton* etwPostFilterSaveDefaultButton_ = nullptr; // Post-filter save default configuration button.
    QPushButton* etwPostFilterImportButton_ = nullptr; // Post-filter import configuration button.
    QPushButton* etwPostFilterExportButton_ = nullptr; // Post-filter export configuration button.
    QLabel* etwPostFilterStateLabel_ = nullptr;      // Post-filter status summary label.
    QScrollArea* etwPostFilterScrollArea_ = nullptr; // Post-filter scroll container.
    QWidget* etwPostFilterGroupHostWidget_ = nullptr; // Post-filter rule group host widget.
    QVBoxLayout* etwPostFilterGroupHostLayout_ = nullptr; // Post-filter rule group layout.
    ProcessTraceTimelineWidget* etwTimelineWidget_ = nullptr; // ETW event waterfall timeline.
    QTableWidget* etwEventTable_ = nullptr;         // ETW event table.
    QTimer* etwUiUpdateTimer_ = nullptr;            // High-frequency ETW UI batch refresh timer.
    QTimer* etwArchiveFilterDebounceTimer_ = nullptr; // ETW full post-filter debounce timer.

    std::vector<EtwProviderEntry> etwProviders_;    // ETW Provider cache.
    QHash<QString, QString> etwCaptureProviderNames_; // Snapshot mapping GUIDs of the current ETW session to display names.
    std::vector<EtwSessionEntry> etwSessions_;      // ETW session cache.
    int etwPreFilterNextGroupId_ = 1;               // Incrementing ID for pre-filter rule groups.
    int etwPostFilterNextGroupId_ = 1;              // Post-filter rule group incrementing ID
    std::vector<std::unique_ptr<EtwFilterRuleGroupUiState>> etwPreFilterRuleGroupUiList_; // Pre-filter UI original rule groups.
    std::vector<std::unique_ptr<EtwFilterRuleGroupUiState>> etwPostFilterRuleGroupUiList_; // Post-filter UI original rule groups
    EtwSimpleFilterCompiled etwPreSimpleFilterCompiled_; // Compiled simple pre-filter.
    EtwSimpleFilterCompiled etwPostSimpleFilterCompiled_; // Compiled simple post-filter.
    std::vector<EtwFilterRuleGroupCompiled> etwPreFilterCompiledGroupList_; // Pre-filter compiled rule groups.
    std::vector<EtwFilterRuleGroupCompiled> etwPostFilterCompiledGroupList_; // Post-filter compiled rule groups.
    std::shared_ptr<const EtwFilterStageCompiledSnapshot> etwPreFilterCompiledSnapshot_; // Pre-filter snapshot used for ETW callbacks.
    std::mutex etwPreFilterSnapshotMutex_;          // Mutex for pre-filter snapshot.
    std::deque<EtwCapturedEventRow> etwPendingRows_; // Bounded FIFO queue for ETW events pending flush to UI.
    std::deque<EtwCapturedEventRow> etwCapturedRows_; // ETW captured event cache (post-filtering only hides).
    std::deque<ProcessTraceTimelineEventPoint> etwTimelineEventPoints_; // Cache of valid time points for ETW timeline rendering.
    std::mutex etwPendingMutex_;                    // ETW pending queue mutex.
    std::atomic<std::uint64_t> etwUiSkippedRows_{ 0 }; // Count of events skipped in the UI mirror only; fully retained in the archive.
    std::atomic<std::uint64_t> etwSourceEventsLost_{ 0 }; // Number of source events lost as reported by the ETW session itself; explicit alert required.
    QElapsedTimer etwTimelineRefreshTimer_;         // Timeline redraw throttling timer.
    QString etwArchiveDirectory_;                  // Full archive directory for the current capture session.
    QString etwArchiveActiveSegmentPath_;          // Current 10-second segment being written.
    QStringList etwArchiveClosedSegmentPaths_;     // Segments that have been sealed and are available for background filtering and reading.
    QByteArray etwArchiveWriteBuffer_;              // Uncompressed aggregation buffer; written as a Zstandard block when approximately 1 MiB.
    std::mutex etwArchiveMutex_;                    // Mutex for writing, sealing, and filtering snapshots.
    std::uintptr_t etwArchiveFileHandle_ = 0;       // Win32 archive file handle; 0 indicates not opened.
    std::uint64_t etwArchiveSegmentStart100ns_ = 0; // Current segment first event timestamp.
    std::uint64_t etwArchiveNextSequence_ = 0;      // Event sequence number for the full archive in this round.
    std::uint32_t etwArchiveSegmentIndex_ = 0;      // Segmented file incrementing index.
    std::atomic_bool etwArchiveWriteFailed_{ false }; // Stop receiving events after any archive write fails.
    std::atomic<std::uint64_t> etwArchiveFilterTicket_{ 0 }; // Background full-scan cancellation ticket.
    std::atomic<std::uint64_t> etwSessionRefreshTicket_{ 0 }; // ETW session enumeration request ticket to prevent stale detached results from being written back.
    std::atomic<std::uint64_t> etwArchiveSessionGeneration_{ 0 }; // Capture session generation to prevent old tasks from reading new sessions.
    std::mutex etwArchiveTaskMutex_;                // Mutex for background filtering/export task lifecycle.
    std::condition_variable etwArchiveTaskCondition_; // Wait for background archive task to exit in destructor.
    std::size_t etwArchiveBackgroundTaskCount_ = 0; // Number of archive background tasks that may still access this object.
    bool etwArchiveTaskShutdown_ = false;            // No new archive background tasks allowed after destructor begins.
    std::atomic_bool etwCaptureRunning_{ false };   // ETW capture running state.
    std::atomic_bool etwCapturePaused_{ false };    // ETW capture paused state.
    std::atomic_bool etwCaptureStopFlag_{ false };  // ETW capture stop flag.
    std::unique_ptr<std::thread> etwCaptureThread_; // ETW background thread.
    int etwCaptureProgressPid_ = 0;                 // ETW capture progress PID.
    int etwSessionRefreshProgressPid_ = 0;          // ETW session refresh/termination progress PID.
    std::atomic<std::uint64_t> etwSessionHandle_{ 0 }; // ETW session handle (TRACEHANDLE).
    std::atomic<std::uint64_t> etwTraceHandle_{ 0 };   // ETW consumer handle (TRACEHANDLE).
    QString etwSessionName_;                        // ETW session name (Stop/Query reuse).
    std::uint64_t etwCaptureStartTime100ns_ = 0;     // ETW timeline left boundary time.
    std::uint64_t etwCaptureStopTime100ns_ = 0;      // ETW timeline stop time right boundary.
    std::uint64_t etwTimelinePauseTime100ns_ = 0;    // Right boundary of the timeline frozen when ETW is paused.
    std::vector<std::pair<std::uint64_t, std::uint64_t>> etwTimelinePauseIntervals_; // List of ETW completed pause intervals.
    std::uint64_t etwTimelineSelectionStart100ns_ = 0; // ETW valid timeline selection start point.
    std::uint64_t etwTimelineSelectionEnd100ns_ = 0;   // ETW valid timeline selection end point.
    bool etwTimelineUserSelectionActive_ = false;    // Whether the user has enabled ETW timeline selection.
    bool wmiInitialDiscoveryDone_ = false;          // m_wmiInitialDiscoveryDone: Whether the WMI page has triggered the initial discovery.
    bool etwInitialDiscoveryDone_ = false;          // m_etwInitialDiscoveryDone: Whether the ETW tab has triggered the initial discovery.
    bool arkRiskCenterInitialDiscoveryDone_ = false; // Whether the risk center has completed its initial summary.
    bool arkRiskRefreshInProgress_ = false;         // Mutex flag for background refresh of the risk center.
    std::uint64_t arkRiskRefreshTicket_ = 0;        // Risk center refresh ticket.
    std::vector<ArkRiskCenterEntry> arkRiskCenterEntries_; // Risk center cache.
};

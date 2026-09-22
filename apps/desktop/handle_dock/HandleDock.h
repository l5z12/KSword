#pragma once

// ============================================================
// HandleDock.h
// Purpose:
// - Provide the 'Handle' Dock page, containing three tabs: 'Handle Table', 'Object Header', and 'Object Type'.
// - The Handle Table page is responsible solely for handle decoding, filtering, and risk marking.
// - The Object Header page is responsible only for the object header, type ownership, and evidence display of the currently selected handle;
// - Object Type page replicates the original kernel object type view and provides type name mapping for the Handle page.
// ============================================================

#include "../Framework.h"
#include "HandleFilterConfig.h"
#include "HandleObjectTypeWorker.h"
#include "../../../shared/driver/KswordArkHandleIoctl.h"

#include <QHash>
#include <QIcon>
#include <QWidget>
#include <QVector>

#include <atomic>
#include <cstdint>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

class QCheckBox;
class QComboBox;
class QHBoxLayout;
class QLabel;
class QLineEdit;
class QPoint;
class QPushButton;
class QShowEvent;
class QSpinBox;
class QTabWidget;
class QTreeWidget;
class QTreeWidgetItem;
class QVBoxLayout;

namespace ks::handle
{
    enum class HandleTreeItemKind : int
    {
        kRuleSummary = 1,
        kHandleRow,
        kLoadMore,
        kLazyPlaceholder
    };

    constexpr int kHandleTreeItemKindRole = Qt::UserRole + 101;
    constexpr int kHandleTreeRuleIdRole = Qt::UserRole + 102;
    constexpr int kHandleTreeRuleOrderRole = Qt::UserRole + 103;
    constexpr int kHandleTreeSourceRowIndexRole = Qt::UserRole + 104;
}

class HandleDock final : public QWidget
{
    Q_OBJECT

public:
    // Constructor purpose:
    // - Create all controls and multi-tab structure for the handle page;
    // - initialize filter conditions, context menu, and asynchronous refresh entry points.
    // Usage: mainWindow creates HandleDock(this).
    // Accepts parent: Qt parent object.
    // Output: none (holds UI and cache via object state).
    explicit HandleDock(QWidget* parent = nullptr);

    // focusProcessId:
    // - When called externally, switch the PID filter box to the target PID.
    // - Automatically switch to the 'Handle List' tab and optionally trigger an immediate refresh.
    // Called by: mainWindow::focusHandleDockByPid invokes this function.
    // Accepts processId (target process PID) and triggerRefresh (whether to refresh immediately).
    // Output: none (internally updates UI state and refresh tasks).
    void focusProcessId(std::uint32_t processId, bool triggerRefresh);
    void focusProcessIds(const QVector<quint32>& processIds, bool triggerRefresh);

protected:
    // showEvent:
    // - Trigger the initial refresh of object types and handles when the page becomes visible for the first time.
    // - Prevents slowing down the main window startup phase with re-queries.
    // Called automatically by Qt.
    // Pass event: the show event object.
    // Output: None.
    void showEvent(QShowEvent* event) override;

private:
    // HandleTableColumn:
    // - Uniformly define handle list column indices to eliminate magic numbers.
    enum class HandleTableColumn : int
    {
        kProcessId = 0,   // ProcessId: owning process PID.
        kProcessName,     // ProcessName: Process name.
        kHandleValue,     // HandleValue: Handle value (hexadecimal).
        kTypeIndex,       // TypeIndex: Object type index.
        kObjectName,      // ObjectName: Object name (may be null).
        kObjectAddress,   // ObjectAddress: Kernel object address (hexadecimal).
        kGrantedAccess,   // GrantedAccess: access mask (hexadecimal).
        kAttributes,      // Attributes: Handle attribute text.
        kHandleCount,     // HandleCount: The object's current HandleCount.
        kPointerCount,    // PointerCount: Current PointerCount of the object.
        kSource,          // Source: This handle originates from a user-mode snapshot, DuplicateHandle resolution, or an R0 HandleTable.
        kDecodeStatus,    // DecodeStatus: R0 decode status or user-mode parse status.
        kDiffStatus,      // DiffStatus: User-mode/R0 difference status.
        kCount            // Count: Total number of columns.
    };

    // ObjectTypeTableColumn:
    // - Unifies the definition of object type page column indices;
    // - Maintains the same semantics as the old KernelDock object type column.
    enum class ObjectTypeTableColumn : int
    {
        kTypeIndex = 0,      // TypeIndex: Type index.
        kTypeName,           // TypeName: Type name.
        kObjectCount,        // ObjectCount: Total number of objects.
        kHandleCount,        // HandleCount: Total number of handles.
        kAccessMask,         // AccessMask: Access mask.
        kSecurityRequired,   // SecurityRequired: Whether security checks are required.
        kMaintainCount,      // MaintainCount: Whether to maintain handle count.
        kCount               // Count: Total number of columns.
    };

    // HandleEnumMode:
    // - Describes the enumeration source used during handle refresh.
    // - UserSnapshot retains the original NtQuerySystemInformation path. DuplicateHandle indicates a user-mode snapshot with object name resolution. KernelHandleTable indicates direct R0 reading of the HandleTable.
    enum class HandleEnumMode : int
    {
        kUserSnapshot = 0,    // UserSnapshot: Snapshot of user-mode system handles only; object name resolution is not forced.
        kDuplicateHandle,     // DuplicateHandle: user-mode snapshot + DuplicateHandle to resolve object count/name.
        kKernelHandleTable    // KernelHandleTable: enumerate the R0 target process's HandleTable.
    };

    // HandleDiffStatus:
    // - Represents the difference relationship between R0 and R3 enumeration paths.
    // - Used for Phase-4 difference view filtering.
    enum class HandleDiffStatus : int
    {
        kNotCompared = 0, // NotCompared: Dual-source comparison not performed in current mode.
        kUserOnly,        // UserOnly: Visible only in user-mode snapshots.
        kKernelOnly,      // KernelOnly: Visible only in the R0 HandleTable.
        kBoth             // Both: Both are visible.
    };

    // HandleRow:
    // - Single handle record for UI display;
    // - All fields are in the final rendered state to avoid secondary conversion on the main thread.
    struct HandleRow
    {
        std::uint32_t processId = 0;       // processId: PID of the process owning the handle.
        std::uint64_t processCreationTime = 0; // processCreationTime: Process creation time; re-verify PID identity before closing.
        QString processName;               // processName: Process name owning the handle.
        std::uint64_t handleValue = 0;     // handleValue: handle value.
        std::uint16_t typeIndex = 0;       // typeIndex: Kernel object type index.
        QString typeName;                  // typeName: Object type name.
        QString objectName;                // objectName: Object name text.
        std::uint64_t objectAddress = 0;   // objectAddress: Object address.
        std::uint32_t grantedAccess = 0;   // grantedAccess: access mask.
        std::uint32_t attributes = 0;      // attributes: Handle attribute bits.
        std::uint32_t handleCount = 0;     // handleCount: object handle count.
        std::uint32_t pointerCount = 0;    // pointerCount: Object pointer count.
        bool basicInfoAvailable = false;   // basicInfoAvailable: Indicates whether ObjectBasicInformation was successfully read.
        bool objectNameAvailable = false;  // objectNameAvailable: Whether the object name query completed successfully (empty string result is allowed).
        bool objectNameFailed = false;     // objectNameFailed: Object name query was attempted but failed.
        bool objectNameFromFallback = false; // objectNameFromFallback: Whether the object name comes from a type-specific fallback query.
        HandleEnumMode sourceMode = HandleEnumMode::kUserSnapshot; // sourceMode: records the primary source of this line.
        HandleDiffStatus diffStatus = HandleDiffStatus::kNotCompared; // diffStatus: R0/R3 difference status.
        std::uint32_t decodeStatus = KSWORD_ARK_HANDLE_DECODE_STATUS_UNAVAILABLE; // decodeStatus: R0 decode status or user-mode parse status.
        std::uint32_t r0FieldFlags = 0; // r0FieldFlags: Field availability bits returned by R0.
        std::uint64_t r0DynDataCapabilityMask = 0; // r0DynDataCapabilityMask: DynData capability when enumerating from R0.
        std::uint32_t epObjectTableOffset = KSWORD_ARK_HANDLE_OFFSET_UNAVAILABLE; // epObjectTableOffset: Offset of EPROCESS.ObjectTable.
        std::uint32_t htHandleContentionEventOffset = KSWORD_ARK_HANDLE_OFFSET_UNAVAILABLE; // htHandleContentionEventOffset: HandleTable unlock offset.
        std::uint32_t obDecodeShift = KSWORD_ARK_HANDLE_OFFSET_UNAVAILABLE; // obDecodeShift: Object pointer decoding shift.
        std::uint32_t obAttributesShift = KSWORD_ARK_HANDLE_OFFSET_UNAVAILABLE; // obAttributesShift: Attribute decoding shift.
        std::uint32_t otNameOffset = KSWORD_ARK_HANDLE_OFFSET_UNAVAILABLE; // otNameOffset: Offset for OBJECT_TYPE.Name.
        std::uint32_t otIndexOffset = KSWORD_ARK_HANDLE_OFFSET_UNAVAILABLE; // otIndexOffset: Offset of OBJECT_TYPE.Index.
    };

    // HandleRefreshOptions:
    // - Packages the main thread's current filter configuration and passes it to the background thread.
    // - Avoid direct access to Qt controls from background threads.
    struct HandleRefreshOptions
    {
        bool hasPidFilter = false;                 // hasPidFilter: Whether PID filtering is enabled.
        std::uint32_t pidFilter = 0;               // pidFilter: Target PID.
        QString keywordText;                       // keywordText: Keyword (lowercase).
        QString typeFilterText;                    // typeFilterText: Type filter text.
        bool onlyNamed = false;                    // onlyNamed: display only handles with object names.
        bool resolveObjectName = true;             // resolveObjectName: Whether to attempt resolving the object name.
        int nameResolveBudget = 300;               // nameResolveBudget: Budget for object name resolution count.
        HandleEnumMode enumMode = HandleEnumMode::kDuplicateHandle; // enumMode: Enumeration mode selected for this refresh cycle.
        HandleDiffStatus diffFilter = HandleDiffStatus::kNotCompared; // diffFilter: Difference status filter.
        std::unordered_map<std::uint16_t, std::string> typeNameCacheByIndex; // typeNameCacheByIndex: Type cache from the previous round.
        std::unordered_map<std::uint16_t, std::string> typeNameMapFromObjectTab; // typeNameMapFromObjectTab: Mapping produced by the object type tab.
    };

    // HandleRefreshResult:
    // - Handle refresh result returned from the background thread to the main thread.
    // - Contains handle rows, type list, and status text.
    struct HandleRefreshResult
    {
        std::vector<HandleRow> rows;               // rows: Filtered handle row results.
        std::vector<QString> availableTypeList;    // availableTypeList: List of available types for this round.
        std::unordered_map<std::uint16_t, std::string> updatedTypeNameCacheByIndex; // updatedTypeNameCacheByIndex: Updated type name cache.
        std::size_t totalHandleCount = 0;          // totalHandleCount: Total number of system handles (enumeration layer).
        std::size_t visibleHandleCount = 0;        // visibleHandleCount: Count of visible handles after filtering.
        std::size_t basicInfoResolvedCount = 0;    // basicInfoResolvedCount: Number of handles for which BasicInformation was successfully read.
        std::size_t resolvedNameCount = 0;         // resolvedNameCount: Number of successfully resolved object names.
        std::size_t fallbackNameCount = 0;         // fallbackNameCount: the number of object names obtained via type-specific fallback.
        std::size_t objectTypeMappedCount = 0;     // objectTypeMappedCount: Count of hits via object type page mapping.
        std::size_t kernelHandleCount = 0;         // kernelHandleCount: Count returned by R0 HandleTable.
        std::size_t userOnlyCount = 0;             // userOnlyCount: Count visible only in user mode in the difference view.
        std::size_t kernelOnlyCount = 0;           // kernelOnlyCount: Count visible only in R0 in the diff view.
        std::size_t bothCount = 0;                 // bothCount: Count of items visible in both sources within the difference view.
        std::uint64_t elapsedMs = 0;               // elapsedMs: Background duration in milliseconds.
        QString diagnosticText;                    // diagnosticText: Diagnostic information (failure/degradation/budget, etc.).
        bool snapshotScopedToPid = false;          // snapshotScopedToPid: Whether this snapshot enumerates only a single PID.
        std::uint32_t scopedProcessId = 0;         // scopedProcessId: Target PID for a single-PID snapshot.
    };

    // ObjectTypeRefreshResult:
    // - Object type refresh result returned from the background thread to the main thread.
    // - Contains a mapping between object type rows and typeIndex.
    struct ObjectTypeRefreshResult
    {
        std::vector<HandleObjectTypeEntry> rows;   // rows: List of object type rows.
        std::unordered_map<std::uint16_t, std::string> typeNameMapByIndex; // typeNameMapByIndex: Type name mapping.
        std::uint64_t elapsedMs = 0;               // elapsedMs: Refresh duration in milliseconds.
        QString diagnosticText;                    // diagnosticText: Diagnostic text.
    };

    // HandleDetailField:
    // - Represents a key-value record in the handle details panel;
    // - Used to asynchronously fill detail results back into the detail tree control.
    struct HandleDetailField
    {
        QString keyText;     // keyText: field name.
        QString valueText;   // valueText: field value.
    };

    // HandleDetailRefreshResult:
    // - Represents the result of a background query for handle details.
    // - Includes common fields, type-specific fields, and diagnostic information.
    struct HandleDetailRefreshResult
    {
        std::vector<HandleDetailField> fields; // fields: Detail key-value list.
        QString diagnosticText;                // diagnosticText: Diagnostic information.
        std::uint64_t elapsedMs = 0;           // elapsedMs: Detail query duration.
    };

    struct HandleRuleMatchState
    {
        QString ruleId;
        QString ruleName;
        bool enabled = true;
        std::vector<std::size_t> rowIndices;
        std::size_t loadedCount = 0;
        QTreeWidgetItem* summaryItem = nullptr;
    };

private:
    // initializeUi:
    // - Create the page layout and multi-tab container;
    // - Build the Handle Table, Object Header, and Object Type tabs.
    // Invocation method: called once inside the constructor.
    // In/Out: None.
    void initializeUi();

    // initializeHandleListTab:
    // - Build the rule toolbar, global collection settings, status bar, and result tree for the Handle Table Tab;
    // - Bind icon buttons with control styles.
    // Called by: initializeUi internally.
    // In/Out: None.
    void initializeHandleListTab();

    // initializeObjectHeaderTab:
    // - Build a read-only details tree for the Object Header Tab;
    // - This page displays the object header, type ownership, and risk flags for the currently selected handle.
    // Called by: initializeUi internally.
    // In/Out: None.
    void initializeObjectHeaderTab();

    // initializeObjectTypeTab:
    // - Build the Object Type Tab (originally the Kernel object type view);
    // - Provide filtering, refresh, and details panel.
    // Called by: initializeUi internally.
    // In/Out: None.
    void initializeObjectTypeTab();

    // initializeHandleTable:
    // - initialize the handle list columns, sorting, and selection behavior.
    // - Unify column widths and right-click policies.
    // Invocation: Called internally by initializeHandleListTab.
    // In/Out: None.
    void initializeHandleTable();

    // initializeObjectTypeTable:
    // - initialize the object type table columns and interaction behavior.
    // - Maintain consistent column semantics with the original KernelDock object type page.
    // Called internally by initializeObjectTypeTab.
    // In/Out: None.
    void initializeObjectTypeTable();

    // initializeConnections:
    // - Link refresh button, filter controls, right-click menu, and details view.
    // - Bind user interactions to the refresh pipeline.
    // Invocation method: called once inside the constructor.
    // In/Out: None.
    void initializeConnections();

    // requestAsyncRefresh:
    // - Initiate an asynchronous handle refresh task.
    // - Uses a ticket to prevent old results from overwriting new ones.
    // Called by: button click, filter change, or initial display.
    // When forceRefresh is true, allow forced refresh; when false, ignore if a task is already in progress.
    // Output: none (results are written back via applyHandleRefreshResult).
    void requestAsyncRefresh(bool forceRefresh);

    // requestAsyncRefreshWithoutTypePrecondition:
    // - Start the actual handle enumeration background task without checking if the object type mapping is ready.
    // - Intended only for the normal path of requestAsyncRefresh and the fallback path when object type snapshot fails.
    // Invocation: Called internally by requestAsyncRefresh and applyObjectTypeRefreshResult.
    // When forceRefresh is true, record pending requests during execution; when false, ignore them during execution.
    // Output: none (results are written back via applyHandleRefreshResult).
    void requestAsyncRefreshWithoutTypePrecondition(bool forceRefresh);

    // requestObjectTypeRefreshAsync:
    // - Initiate an asynchronous object type refresh task.
    // - On success, update the typeIndex->typeName mapping for reuse during handle enumeration.
    // Called by: object type page refresh button or initial display.
    // Pass forceRefresh: true to force refresh; false to ignore concurrency.
    // Output: none (results are filled back via applyObjectTypeRefreshResult).
    void requestObjectTypeRefreshAsync(bool forceRefresh);

    // applyHandleRefreshResult:
    // - Apply handle refresh results on the main thread;
    // - Update the cache, type dropdown, and status text, and refresh the table once the type mapping becomes available.
    // Usage: invokeMethod callback is triggered after background task completion.
    // Input: refreshTicket (task sequence number); refreshResult (background result object).
    // Output: None.
    void applyHandleRefreshResult(std::uint64_t refreshTicket, const HandleRefreshResult& refreshResult);

    // applyObjectTypeRefreshResult:
    // - Apply object type refresh results on the main thread;
    // - Update the object type table and type mapping cache, and flush handle type names.
    // Invocation method: Callback after object type background task completion.
    // Input: refreshTicket (task sequence number); refreshResult (background result object).
    // Output: None.
    void applyObjectTypeRefreshResult(std::uint64_t refreshTicket, const ObjectTypeRefreshResult& refreshResult);

    // rebuildHandleTable:
    // - Rebuild the summary tree based on rule match status without automatically creating full handle rows;
    // - Details are created in batches of 300 based on rule expansion events.
    // Called by: applyHandleRefreshResult / syncHandleTypeNamesFromObjectTypeMap internally.
    // In/Out: None.
    void rebuildHandleTable();

    // applyLocalHandleFilters:
    // - Apply local filters to the current complete handle snapshot without re-enumerating system handles.
    // - Used for lightweight interactions such as PID, type, and keywords to avoid repeated heavy refreshes.
    // Call when filter conditions change, or after handle refresh completes and rendering is possible.
    // In/Out: None.
    void applyLocalHandleFilters();

    // applyLocalHandleFilters:
    // - Performs local filtering on the current complete handle snapshot and rebuilds the GUI table as needed;
    // - When handle enumeration completes but object type mapping has not yet arrived, only update the m_rows cache without triggering table rendering.
    // Called by: applyHandleRefreshResult, syncHandleTypeNamesFromObjectTypeMap, applyLocalHandleFilters.
    // Input: rebuildTable (true to rebuild the table immediately; false to update only the filter cache).
    // Output: None.
    void applyLocalHandleFilters(bool rebuildTable);

    void rebuildRuleSummaryTree();
    void appendNextRuleResultBatch(const QString& ruleId);
    QTreeWidgetItem* createHandleTreeRow(std::size_t sourceRowIndex);
    void scheduleProcessIconResolution(
        const QVector<qulonglong>& sourceRowIndices,
        const QVector<QTreeWidgetItem*>& itemList);
    HandleRuleMatchState* findRuleMatchState(const QString& ruleId);
    const HandleRuleMatchState* findRuleMatchState(const QString& ruleId) const;
    const ks::handle::HandleFilterRule* findActiveRule(const QString& ruleId) const;
    bool handleRowMatchesRule(
        const HandleRow& row,
        const ks::handle::HandleFilterRule& rule) const;
    void updateHandleSummaryStatus();
    void sortLoadedRuleRows(int column, Qt::SortOrder order);

    void loadFilterConfiguration();
    void saveFilterConfiguration() const;
    void applyFilterGlobalSettingsToControls();
    void collectFilterGlobalSettingsFromControls();
    void showRuleManagerDialog(const QString& initiallySelectedRuleId = QString());
    bool showRuleEditorDialog(
        ks::handle::HandleFilterRule* ruleInOut,
        const QVector<ks::handle::HandleFilterRule>& existingRules);
    void importFilterConfiguration();
    void exportFilterConfiguration() const;
    void exportRuleResults(const QString& ruleId = QString()) const;
    void returnToSavedFilters();
    QString buildRuleConditionSummary(const ks::handle::HandleFilterRule& rule) const;

    // rebuildObjectTypeTable:
    // - Rebuild the object type table based on m_objectTypeRows;
    // - Supports filtering type names and IDs by keyword.
    // Called by: object type refresh completion or filter box change.
    // Input filterKeyword: filter keyword (may be empty).
    // Output: None.
    void rebuildObjectTypeTable(const QString& filterKeyword);

    // collectHandleRefreshOptions:
    // - Read collection configuration from persistent global settings and encapsulate into a thread-safe structure;
    // - Only allows narrowing the background enumeration scope for temporary single-PID filtering.
    // Called by: requestAsyncRefresh internally.
    // Input/Output: none. Returns HandleRefreshOptions.
    HandleRefreshOptions collectHandleRefreshOptions() const;

    // updateTypeFilterItems:
    // - Rebuild the 'Type Filter' dropdown based on the refresh result.
    // - Preserves user's previous selection to avoid reset after refresh.
    // Called by: applyHandleRefreshResult internally.
    // Input availableTypeList: the type list for this round.
    // Output: None.
    void updateTypeFilterItems(const std::vector<QString>& availableTypeList);

    // refreshTypeFilterItemsFromAllRows:
    // - Rebuild the type filter dropdown based on the complete handle snapshot.
    // - Used to synchronize filter options after object type mapping updates.
    // Called by: applyHandleRefreshResult and syncHandleTypeNamesFromObjectTypeMap.
    // In/Out: None.
    void refreshTypeFilterItemsFromAllRows();

    // syncHandleTypeNamesFromObjectTypeMap:
    // - After the object type page refresh completes, synchronize the type names of currently cached handle rows in place.
    // - Avoid triggering another heavy handle enumeration to reduce UI lag.
    // Usage: Called internally by applyObjectTypeRefreshResult.
    // In/Out: None.
    void syncHandleTypeNamesFromObjectTypeMap();

    // requestHandleDetailRefresh:
    // - Asynchronously fetch detailed information for the currently selected handle.
    // - Details include common fields and type-specific information in branches.
    // Invocation: Called when switching selected rows or manually refreshing details.
    // Input forceRefresh: true forces refresh; false ignores on concurrency.
    // Output: None.
    void requestHandleDetailRefresh(bool forceRefresh);

    // applyHandleDetailRefreshResult:
    // - Apply asynchronous handle detail results on the main thread;
    // - Populate the detail table and status text.
    // Invocation method: Callback after the detail background task completes.
    // Parameters: refreshTicket is the detail refresh sequence number; refreshResult is the detail result.
    // Output: None.
    void applyHandleDetailRefreshResult(std::uint64_t refreshTicket, const HandleDetailRefreshResult& refreshResult);

    // updateHandleStatusLabel:
    // - Uniformly updates the handle page status label text and color.
    // - Use different styles for refreshing and completed states.
    // Usage: Called by requestAsyncRefresh and applyHandleRefreshResult.
    // Parameters: statusText (display text); refreshing (whether currently refreshing).
    // Output: None.
    void updateHandleStatusLabel(const QString& statusText, bool refreshing);

    // updateObjectTypeStatusLabel:
    // - Updates the object type page status label text and color.
    // - Used to display the object type refresh status.
    // Called by requestObjectTypeRefreshAsync and applyObjectTypeRefreshResult.
    // Accepts statusText: status text; refreshing: whether currently refreshing.
    // Output: None.
    void updateObjectTypeStatusLabel(const QString& statusText, bool refreshing);

    // focusObjectTypeByIndex:
    // - Switch to the object type tab and locate the specified typeIndex.
    // - If no match is found, only set the filter condition.
    // Called when right-clicking 'Go to Object Type' in the handle list.
    // Input typeIndex: target type index.
    // Output: None.
    void focusObjectTypeByIndex(std::uint16_t typeIndex);

    // showHandleTableContextMenu:
    // - Display the right-click context menu on the handle table;
    // - Provides only read-only actions such as copy, jump, and refresh.
    // Invocation: QTreeWidget::customContextMenuRequested callback.
    // Pass localPosition: table local coordinates.
    // Output: None.
    void showHandleTableContextMenu(const QPoint& localPosition);

    // showHandleHeaderContextMenu:
    // - Show column management menu on the handle header;
    // - Supports showing/hiding columns to complete the basic column system capabilities.
    // Invocation: QHeaderView::customContextMenuRequested callback.
    // Pass localPosition: header local coordinates.
    // Output: None.
    void showHandleHeaderContextMenu(const QPoint& localPosition);

    // showObjectTypeDetailByCurrentRow:
    // - Refresh the detail text based on the current row in the object type table.
    // - Replicate the original KernelDock object type details.
    // Invocation method: currentCellChanged callback.
    // In/Out: None.
    void showObjectTypeDetailByCurrentRow();

    // showHandleDetailPlaceholder:
    // - Display placeholder content when no handle is selected or details are not ready;
    // - Avoid residual old data in the detail area.
    // Usage: Called during initialization or when no item is selected after filtering.
    // Takes messageText: placeholder description text.
    // Output: None.
    void showHandleDetailPlaceholder(const QString& messageText);

    // selectedHandleRow:
    // - Read the cached record corresponding to the currently selected handle row.
    // - Returns a mutable pointer for action functions to use.
    // Invocation: Call before executing the right-click action.
    // Parameters/Return: None; returns HandleRow* (returns nullptr if no selection).
    HandleRow* selectedHandleRow();

    // copyCurrentHandleCell:
    // - Copy the text of the current handle cell to the clipboard.
    // - Used for quick auditing of field values.
    // Invocation method: Right-click menu "Copy Cell".
    // In/Out: None.
    void copyCurrentHandleCell();

    // copyCurrentHandleRow:
    // - Copy the current handle row (TAB-separated) to the clipboard.
    // - Facilitates pasting into table tools or logs.
    // Invocation method: right-click menu 'Copy entire row'.
    // In/Out: None.
    void copyCurrentHandleRow();

    // closeCurrentHandle:
    // - Execute DuplicateHandle(DUPLICATE_CLOSE_SOURCE) on the selected handle;
    // - Automatically trigger a refresh upon success.
    // - The current default UI no longer exposes this entry point.
    // In/Out: None.
    void closeCurrentHandle();

    // closeSameTypeHandlesInCurrentProcess:
    // - Close a set of handles with the same PID and TypeIndex.
    // - Used for batch handling of anomalous handles to improve handle management capabilities.
    // - The current default UI no longer exposes this entry point.
    // In/Out: None.
    void closeSameTypeHandlesInCurrentProcess();

    // buildHandleRefreshResult:
    // - Core background thread: enumerate system handles and filter by condition.
    // - Prefer generating type name from object type page mapping, then supplement with fallback query;
    // Called by: requestAsyncRefresh (invoked on a background thread).
    // Pass options: refresh configuration.
    // Output: HandleRefreshResult (returned by value).
    static HandleRefreshResult buildHandleRefreshResult(const HandleRefreshOptions& options);

    // buildObjectTypeRefreshResult:
    // - Background thread core: refresh object type snapshots and build the typeIndex mapping;
    // - Shared between the Object Type tab and the handle list.
    // Usage: requestObjectTypeRefreshAsync is called on a background thread.
    // Input: None.
    // Output: ObjectTypeRefreshResult (returned by value).
    static ObjectTypeRefreshResult buildObjectTypeRefreshResult();

    // closeRemoteHandle:
    // - Encapsulate Win32 operations for closing remote process handles.
    // - Returns a boolean result and detailed error text.
    // Called by: closeCurrentHandle / closeSameTypeHandlesInCurrentProcess.
    // Parameters: processId (target PID); handleValue (target handle value).
    // Outputs detailTextOut: action details; returns true/false.
    static bool closeRemoteHandle(const HandleRow& expectedRow, std::string& detailTextOut);

    // buildHandleDetailRefreshResult:
    // - Background thread core: generates specialized details based on handle type.
    // - Supports enhanced display for File, Key, Process, Thread, Token, Section, Event, and Mutant types.
    // Called from a thread pool via requestHandleDetailRefresh.
    // Accepts row: snapshot of the currently selected handle row.
    // Returns: HandleDetailRefreshResult (by value).
    static HandleDetailRefreshResult buildHandleDetailRefreshResult(const HandleRow& row);

    // formatHex: Converts values to hexadecimal text with a 0x prefix.
    // Called during table rendering.
    // Accepts value: 64-bit value; width: minimum width (zero-padded).
    // Output: QString text.
    static QString formatHex(std::uint64_t value, int width = 0);

    // formatOptionalObjectCount:
    // - Standardize formatting of HandleCount/PointerCount text;
    // - Distinguishes between 'value is 0' and 'not found' states.
    // Called when rendering the handle list and details panel.
    // Input: countValue (counter field value); countAvailable (whether the query succeeded).
    // Output: QString text.
    static QString formatOptionalObjectCount(std::uint32_t countValue, bool countAvailable);

    // formatObjectNameDisplayText:
    // - Uniformly formats the object name column and detail panel text.
    // - Distinguish between four states: 'not queried', 'not found', 'no name', and 'has name'.
    // Called when rendering the handle list and details panel.
    // Input row: current handle row data.
    // Output: QString text.
    static QString formatObjectNameDisplayText(const HandleRow& row);

    // formatTypeIndexDisplayText:
    // - Format the TypeIndex column as readable text: 'TypeName + Index'.
    // - Display as "Directory (50)" when the type is resolved; otherwise, display only the index.
    // Called when rendering the handle table and synchronizing type names.
    // Accepts typeIndex: the type index; typeName: the type name.
    // Output: QString text.
    static QString formatTypeIndexDisplayText(std::uint16_t typeIndex, const QString& typeName);

    // formatHandleAttributes:
    // - Convert handle attribute bits to readable text (INHERIT/PROTECT/AUDIT);
    // - Fall back to "None" on miss.
    // Called during table rendering.
    // Input attributes: original attribute bits.
    // Output: QString text.
    static QString formatHandleAttributes(std::uint32_t attributes);

    // formatHandleSourceText: Converts the source line enumeration to UI text.
    // Called during handle table rendering, detail panel display, and filtering.
    // Input mode: source enumeration value.
    // Output: QString text.
    static QString formatHandleSourceText(HandleEnumMode mode);

    // formatHandleDecodeStatusText: Convert R0 decode status or user-mode status to UI text.
    // Called during handle table rendering, detail panel display, and filtering.
    // Accepts status: KSWORD_ARK_HANDLE_DECODE_STATUS_*.
    // Output: QString text.
    static QString formatHandleDecodeStatusText(std::uint32_t status);

    // formatHandleDiffStatusText: Converts the difference status into UI text.
    // Called during handle table rendering, detail panel display, and filtering.
    // Accepts status: HandleDiffStatus.
    // Output: QString text.
    static QString formatHandleDiffStatusText(HandleDiffStatus status);

    // resolveHandleEnumModeFromText: Convert UI dropdown text to an enumeration mode.
    // Called by: internal call within collectHandleRefreshOptions.
    // Input modeText: current text from the dropdown.
    // Out: HandleEnumMode.
    static HandleEnumMode resolveHandleEnumModeFromText(const QString& modeText);

    // resolveHandleDiffFilterFromText: Converts UI dropdown text to a difference filter enum.
    // Called by: collectHandleRefreshOptions/applyLocalHandleFilters internally.
    // Takes filterText: current text in the dropdown.
    // Output: HandleDiffStatus.
    static HandleDiffStatus resolveHandleDiffFilterFromText(const QString& filterText);

    // resolveProcessIconForRow:
    // - Only resolve and cache process icons for PID + creation time instances present in the current handle snapshot;
    // - Return the default icon when the instance cannot be confirmed to avoid incorrect path or icon attribution after PID reuse.
    // Called when rebuilding the handle table.
    // Input row: a handle snapshot row carrying the process instance identity.
    // Output: QIcon for the process icon; falls back to the default icon if the instance cannot be confirmed.
    QIcon resolveProcessIconForRow(const HandleRow& row);

    // queryProcessImagePathCached:
    // - Query and cache the image path corresponding to the specified process instance;
    // - Validate and query the path using the same process handle to avoid mismatches caused by PID reuse.
    // Called by: resolveProcessIconForRow internally.
    // Accepts processId and expectedCreationTime as the target process instance identity.
    // Returns: QString process path; returns an empty string if identity cannot be confirmed or the query fails.
    QString queryProcessImagePathCached(std::uint32_t processId, std::uint64_t expectedCreationTime);

    // decodeGrantedAccessText:
    // - Translate the GrantedAccess bitmask into semantic permission text based on the object type.
    // - Used to enhance readability in list tooltips and detail panels.
    // Invocation method: Called during handle table rendering and detail construction.
    // Pass typeName: object type name; grantedAccess: access mask.
    // Out: QString semantic permission text.
    static QString decodeGrantedAccessText(const QString& typeName, std::uint32_t grantedAccess);

private:
    QVBoxLayout* rootLayout_ = nullptr;         // m_rootLayout: Page root layout.
    QTabWidget* tabWidget_ = nullptr;           // m_tabWidget: Handle module Tab container.

    QWidget* handleListPage_ = nullptr;         // m_handleListPage: Handle Table page container.
    QVBoxLayout* handleListLayout_ = nullptr;   // m_handleListLayout: Handle Table page layout.
    QHBoxLayout* toolbarLayout_ = nullptr;      // m_toolbarLayout: Handle Table top toolbar layout.
    QPushButton* refreshButton_ = nullptr;      // m_refreshButton: Handle refresh button (iconified).
    QPushButton* manageFilterButton_ = nullptr;
    QPushButton* importFilterButton_ = nullptr;
    QPushButton* exportFilterButton_ = nullptr;
    QPushButton* exportResultsButton_ = nullptr;
    QPushButton* returnSavedFilterButton_ = nullptr;
    QComboBox* enumModeCombo_ = nullptr;        // m_enumModeCombo: Enumeration mode dropdown.
    QCheckBox* resolveNameCheckBox_ = nullptr;  // m_resolveNameCheckBox: Enable object name resolution.
    QSpinBox* nameBudgetSpinBox_ = nullptr;     // m_nameBudgetSpinBox: Object name resolution budget.
    QLabel* statusLabel_ = nullptr;             // m_statusLabel: Handle refresh status text.
    QTreeWidget* tableWidget_ = nullptr;        // m_tableWidget: Handle list table.
    QWidget* objectHeaderPage_ = nullptr;       // m_objectHeaderPage: Object Header page container.
    QVBoxLayout* objectHeaderLayout_ = nullptr; // m_objectHeaderLayout: Object Header page layout.
    QLabel* handleDetailStatusLabel_ = nullptr; // m_handleDetailStatusLabel: Object Header status text.
    QTreeWidget* handleDetailTable_ = nullptr;  // m_handleDetailTable: Object Header key-value table.

    QWidget* objectTypePage_ = nullptr;         // m_objectTypePage: Object Type page container.
    QVBoxLayout* objectTypeLayout_ = nullptr;   // m_objectTypeLayout: Object Type page layout.
    QHBoxLayout* objectTypeToolLayout_ = nullptr; // m_objectTypeToolLayout: Object Type toolbar layout.
    QPushButton* refreshObjectTypeButton_ = nullptr; // m_refreshObjectTypeButton: Object type refresh button.
    QLineEdit* objectTypeFilterEdit_ = nullptr; // m_objectTypeFilterEdit: Object type filter input box.
    QLabel* objectTypeStatusLabel_ = nullptr;   // m_objectTypeStatusLabel: Object type status text.
    QTreeWidget* objectTypeTable_ = nullptr;    // m_objectTypeTable: Object type list table.
    QTreeWidget* objectTypeDetailTable_ = nullptr; // m_objectTypeDetailTable: Object type details (key-value table).

    bool refreshInProgress_ = false;            // m_refreshInProgress: Mutex flag for handle refresh.
    bool refreshPending_ = false;               // m_refreshPending: Pending refresh requests recorded during an ongoing refresh.
    bool objectTypeRefreshInProgress_ = false;  // m_objectTypeRefreshInProgress: Object type refresh in-progress flag.
    bool objectTypeRefreshPending_ = false;     // m_objectTypeRefreshPending: Object type refresh pending request flag.
    bool handleDetailRefreshInProgress_ = false; // m_handleDetailRefreshInProgress: Mutex flag for handle detail refresh.
    bool handleDetailRefreshPending_ = false;   // m_handleDetailRefreshPending: Flag for pending handle detail refresh requests.
    bool handleRenderDeferredUntilTypeMap_ = false; // m_handleRenderDeferredUntilTypeMap: Handle enumeration is complete, but table rendering is waiting for object type mapping.
    bool initialRefreshDone_ = false;           // m_initialRefreshDone: Flag indicating whether the first refresh is complete.
    std::uint64_t refreshTicket_ = 0;           // m_refreshTicket: Handle refresh sequence number to prevent out-of-order overwrites.
    std::uint64_t objectTypeRefreshTicket_ = 0; // m_objectTypeRefreshTicket: Object type refresh sequence number.
    std::uint64_t handleDetailRefreshTicket_ = 0; // m_handleDetailRefreshTicket: Handle detail refresh sequence number.
    int refreshProgressPid_ = 0;                // m_refreshProgressPid: Handle refresh kPro task PID.
    int objectTypeRefreshProgressPid_ = 0;      // m_objectTypeRefreshProgressPid: PID of the kPro task for refreshing object types.
    int handleDetailRefreshProgressPid_ = 0;    // m_handleDetailRefreshProgressPid: PID of the handle detail refresh kPro task.

    std::vector<HandleRow> allRows_;            // m_allRows: Complete handle snapshot cache.
    std::vector<HandleRow> rows_;               // Compatible with the legacy full-table rendering path; the rule tree uses m_allRows for indexing.
    ks::handle::HandleFilterDocument filterDocument_;
    ks::handle::HandleFilterRule temporaryFilterRule_;
    bool temporaryFilterActive_ = false;
    bool snapshotScopedToTemporarySinglePid_ = false;
    std::uint32_t snapshotScopedProcessId_ = 0;
    std::vector<HandleRuleMatchState> ruleMatchStates_;
    std::vector<QString> availableHandleTypeList_;
    std::size_t totalRuleMatchCount_ = 0;
    std::size_t lastEnumeratedHandleCount_ = 0;
    std::size_t lastResolvedNameCount_ = 0;
    std::size_t lastObjectTypeMappedCount_ = 0;
    std::size_t lastKernelHandleCount_ = 0;
    std::uint64_t lastRefreshElapsedMs_ = 0;
    QString lastRefreshDiagnosticText_;
    int handleSortColumn_ = -1;
    Qt::SortOrder handleSortOrder_ = Qt::AscendingOrder;
    std::vector<HandleObjectTypeEntry> objectTypeRows_; // m_objectTypeRows: Object type row cache.
    std::unordered_map<std::uint16_t, std::string> typeNameCacheByIndex_; // m_typeNameCacheByIndex: Type cache generated during the handle refresh phase.
    std::unordered_map<std::uint16_t, std::string> typeNameMapByIndexFromObjectTab_; // m_typeNameMapByIndexFromObjectTab: Cache mapping object type page indices.
    QHash<QString, QIcon> processIconCacheByIdentity_; // m_processIconCacheByIdentity: PID + creation time -> icon cache.
    QHash<QString, QString> processImagePathCacheByIdentity_; // m_processImagePathCacheByIdentity: PID + creation time -> path cache.
    std::uint64_t processIconResolveGeneration_ = 0; // m_processIconResolveGeneration: Generation counter for background process icon resolution; increments when rebuilding the handle table to invalidate in-flight results.
    std::shared_ptr<std::atomic_bool> processIconResolveCancelFlag_; // m_processIconResolveCancelFlag: Background process icon resolution cancellation flag; set during handle table rebuild to force the previous scan to exit quickly.
    std::vector<QTreeWidgetItem*> handleTableItemsByRowIndex_; // Compatible with legacy full-table icon fill paths.
};

#pragma once

#include "KernelFacade.h"
#include "KernelCallbackEventReceiver.h"
#include "KernelModel.h"
#include "../../core/Win32Lean.h"
#include "../../ui/AsyncTask.h"

#include <cstdint>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

namespace ksword::features::kernel {

struct KernelObjectNamespaceTreeNodeState;

// KernelR0EvidenceSnapshot is the immutable result of a client-side R0
// evidence projection. Worker tasks own this value completely before the UI
// applies it to the owner-data ListView.
struct KernelR0EvidenceSnapshot {
    KernelFeatureId featureId = KernelFeatureId::kCpuHardwareSnapshot;
    std::vector<std::wstring> columns;
    std::vector<std::vector<std::wstring>> rows;
    std::wstring statusText;
    std::wstring selectedRowSignature;
    int topRow = 0;
};

enum class CallbackFileIoOperation {
    kImportConfig,
    kExportConfig,
    kExportFileMonitor,
    kExportResultTsv,
    kCallbackModuleDetail,
    kMapNtPath,
    kOpenModuleFolder
};

// CallbackFileIoResult is the immutable boundary for callback-rule files and
// file-monitor exports. Picker dialogs and model application remain on the UI
// thread; file reads and writes are performed by a dedicated worker task.
struct CallbackFileIoResult {
    CallbackFileIoOperation operation = CallbackFileIoOperation::kImportConfig;
    std::wstring path;
    std::wstring text;
    std::wstring clipboardText;
    std::wstring errorText;
};

// KernelPage is the lightweight Win32 UI for retained kernel entries. Inputs are
// parent HWND and bounds during Create; processing owns child controls and sends
// model requests to KernelFacade; return behavior is HWND-based like normal
// Win32 pages, with no direct driver or protocol access from this UI class.
class KernelPage final {
public:
    KernelPage();
    ~KernelPage();

    KernelPage(const KernelPage&) = delete;
    KernelPage& operator=(const KernelPage&) = delete;

    // Create registers and creates the child page window. Inputs are parent,
    // control id, and bounds; processing stores this object in GWLP_USERDATA;
    // output is the created HWND or nullptr on failure.
    HWND create(HWND parent, int controlId, const RECT& bounds);

    // setInitialFeature selects a retained kernel feature after Create builds
    // the controls. Input is a stable KernelFeatureId; processing stores it
    // until populateTabs runs, then either selects a visible dock tab or enters
    // direct single-feature mode for pages hidden from the Kernel dock. There
    // is no return value.
    void setInitialFeature(KernelFeatureId featureId) noexcept;

    // Window returns the page HWND. There is no input; output can be null before
    // Create succeeds or after WM_NCDESTROY.
    HWND window() const noexcept { return hwnd_; }

    // WndProc is public only so the local Win32 class-registration helper can
    // bind it to WNDCLASSW. Inputs are normal Win32 procedure parameters;
    // processing dispatches to the KernelPage stored in GWLP_USERDATA; output is
    // a normal Win32 LRESULT.
    static LRESULT CALLBACK wndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
    static LRESULT CALLBACK filterEditSubclassProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam,
        UINT_PTR subclassId, DWORD_PTR refData);

private:
    LRESULT handleMessage(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);

    void createChildControls();
    void layout();
    void populateTabs();
    void onFeatureSelectionChanged();
    void refreshSelectedFeature();
    void executeActionInBackground(KernelActionRequest request, KernelActionId actionId, bool offerForcedRetry);
    void locateNextResult();
    void executeObjectNamespaceToolbarAction();
    void executeObjectNamespaceDetailAction();
    void fillIntegrityInputsFromSelection();
    void refreshKernelCpuIntegrityFromDriverPage();
    void executeSelectedAction(KernelActionId actionId);
    KernelRequest buildCurrentRequest(KernelFeatureId featureId) const;
    KernelActionRequest buildCurrentActionRequest(KernelActionId actionId) const;
    void renderDescriptor(const KernelFeatureDescriptor& descriptor);
    void renderResult(const KernelOperationResult& result);
    void rebuildObjectNamespaceListFromCache(KernelFeatureId featureId);
    void toggleObjectNamespaceListNode(int rowIndex);
    void rebuildObjectNamespaceTreeFromCurrentRows();
    void selectObjectNamespaceTreeItem(LPARAM itemData);
    void selectObjectNamespaceTreeRow(LPARAM rowIndex);
    void rebuildAtomTableFromCache();
    void rebuildNtQueryLegacyListFromCache();
    void rebuildDiagnosticDualTableFromCache(KernelFeatureId featureId);
    void rebuildCallbackEnumerationListFromCache();
    void rebuildKernelHookListFromCache(KernelFeatureId featureId);
    void rebuildKernelMemoryScanListFromCache(KernelFeatureId featureId);
    void rebuildCrossViewListFromCache(KernelFeatureId featureId);
    void rebuildIntegrityEvidenceListFromCache(KernelFeatureId featureId);
    void rebuildR0EvidenceListFromCache(KernelFeatureId featureId);
    void scheduleR0EvidenceFilter(KernelFeatureId featureId);
    void requestR0EvidenceRebuild(KernelFeatureId featureId);
    void applyR0EvidenceSnapshot(KernelR0EvidenceSnapshot snapshot);
    const KernelFeatureDescriptor* currentDescriptor() const;
    const KernelFeatureDescriptor* featureById(KernelFeatureId featureId) const;
    void rebuildSecondLevelTabs();
    void selectCurrentFeature();
    bool selectFeatureById(KernelFeatureId featureId);
    void parkCurrentFeatureViewCache();
    void saveCurrentFeatureViewCache(bool transferDataToCache);
    void invalidateCurrentFeatureViewCache();
    bool restoreFeatureViewCache(KernelFeatureId featureId);
    void resetVisibleResultRows();
    void syncResultListVirtualRows();
    void ensureResultColumnsForCurrentFeature();
    std::vector<std::vector<std::wstring>> captureReportListRows(HWND list) const;
    void restoreReportListRows(HWND list, const std::vector<std::vector<std::wstring>>& rows);
    std::wstring resultCellText(int row, int column) const;
    std::wstring visibleCellText(int row, int column) const;
    bool currentPrimaryUsesSecondaryTabs() const;
    void addDynamicResultColumns(const KernelOperationResult& result, std::vector<std::wstring>& orderedColumns);
    void addDynamicResultRow(int rowIndex, const KernelResultRow& resultRow, const std::vector<std::wstring>& orderedColumns);
    void rebuildResultListFromCache();
    void sortResultRowsByColumn(int columnIndex);
    void updateSelectedRowDetail();
    LRESULT handleResultListCustomDraw(LPARAM lParam);
    void updatePropertyTableFromSelection();
    void updateSummaryTableFromRows();
    void configureVisibleLayout();
    void configureToolbarForDescriptor(const KernelFeatureDescriptor& descriptor);
    void populateCallbackInterceptPanel();
    void startCallbackEventReceiver();
    void stopCallbackEventReceiver();
    void acceptCallbackEvent(CallbackEventSnapshot snapshot);
    void answerCurrentCallbackEvent(bool allow);
    void refreshCallbackEventLog();
    void ensureCallbackLocalModel();
    void renderCallbackLocalModel();
    void appendCallbackAppLog(const std::wstring& message);
    int callbackSelectedRuleTabIndex() const;
    int callbackSelectedGroupRow() const;
    int callbackSelectedRuleRow() const;
    std::uint32_t callbackSelectedGroupId() const;
    void onCallbackAddGroup();
    void onCallbackRemoveGroup();
    void onCallbackRenameGroup();
    void onCallbackMoveGroup(bool moveUp);
    void onCallbackToggleGroupEnabled();
    void onCallbackAddRule();
    void onCallbackRemoveRule();
    void onCallbackMoveRule(bool moveUp);
    void onCallbackToggleRuleEnabled();
    void onCallbackCopyRuleText();
    void onCallbackPasteRuleText();
    void onCallbackBypassAdd();
    void onCallbackBypassRemove();
    void onCallbackImportConfig();
    void onCallbackExportConfig();
    void onCallbackExportFileMonitor();
    void openCallbackFileMonitorProcess();
    void openCallbackFileMonitorPath();
    void startCallbackFileIo(CallbackFileIoOperation operation, std::wstring path, std::wstring text = {});
    void applyCallbackFileIoResult(CallbackFileIoResult result);
    void setCallbackFileIoControlsEnabled(bool enabled);
    void showCallbackInterceptContextMenu(HWND source, POINT screenPoint);
    void copyCallbackPanelSelection(HWND source);
    std::wstring serializeCallbackLocalConfig() const;
    bool loadCallbackLocalConfig(const std::wstring& text, std::wstring* errorText);
    bool callbackRulesGlobalEnabled() const;
    std::uint32_t currentIncludeFlags() const;
    std::wstring buildOriginalStyleSelectedRowDetail(KernelFeatureId featureId, int row) const;
    bool prepareResultContextPoint(POINT& screenPoint, bool updatePropertyTable);
    void showResultContextMenu(POINT screenPoint);
    bool showAtomTableContextMenu(POINT screenPoint, const KernelFeatureDescriptor& descriptor);
    bool showNtQueryContextMenu(POINT screenPoint, const KernelFeatureDescriptor& descriptor);
    bool showObjectNamespaceContextMenu(POINT screenPoint, const KernelFeatureDescriptor& descriptor);
    bool showObjectNamespaceOverviewContextMenu(POINT screenPoint, const KernelFeatureDescriptor& descriptor);
    bool showObjectDirectoryRecursiveContextMenu(POINT screenPoint, const KernelFeatureDescriptor& descriptor);
    bool showNamedPipeContextMenu(POINT screenPoint, const KernelFeatureDescriptor& descriptor);
    bool showSymbolicLinkContextMenu(POINT screenPoint, const KernelFeatureDescriptor& descriptor);
    bool showObjectTypeMatrixContextMenu(POINT screenPoint, const KernelFeatureDescriptor& descriptor);
    bool showCommunicationEndpointContextMenu(POINT screenPoint, const KernelFeatureDescriptor& descriptor);
    bool showDeviceDriverObjectsContextMenu(POINT screenPoint, const KernelFeatureDescriptor& descriptor);
    bool showSimpleObjectTableContextMenu(POINT screenPoint, const KernelFeatureDescriptor& descriptor);
    bool showKernelHookContextMenu(POINT screenPoint, const KernelFeatureDescriptor& descriptor);
    bool showCallbackEnumerationContextMenu(POINT screenPoint, const KernelFeatureDescriptor& descriptor);
    bool showR0EvidenceContextMenu(POINT screenPoint, const KernelFeatureDescriptor& descriptor);
    void applySelectedModuleFilter(bool preferTargetModule);
    void applySelectedAddressFilter();
    void applySelectedPathFilter();
    bool rebuildCurrentObjectNamespaceFilter(const wchar_t* statusText);
    void applySelectedOwnerFilter();
    void applySelectedRiskFilter();
    void applySelectedPidTidFilter();
    void applySelectedCapabilityFilter();
    void showSelectedRowDialog();
    void copySelectedCell();
    void copySelectedRow();
    void copySelectedRows(bool includeHeader);
    void copySelectedDetails();
    void copySelectedColumn(int columnIndex);
    std::wstring buildSelectedRowsTsv(bool includeHeader) const;
    std::wstring buildRowDetailText(int row) const;
    std::vector<int> currentCopyColumnIndices() const;
    void copyAllRows();
    void copyDiagnosticReport();
    std::wstring buildDiagnosticReportForCurrentFeature() const;
    void exportAllRowsTsv();
    void applySelectedTypeFilter();
    void applySelectedNameFilter();
    void applySelectedTargetFilter();
    void verifySelectedAtom();
    void copySelectedAtomSnippet();
    void copyRowsWithSameDirectory();
    void mapSelectedNtPathAsDosPaths();
    void openSelectedCallbackModuleFolder();
    void showSelectedCallbackModuleFileDetail();
    std::wstring selectedCallbackModulePath() const;
    std::wstring normalizeCallbackModulePath(const std::wstring& modulePath) const;
    void copyPreferredSelectedField(std::initializer_list<std::wstring> fieldNames, const wchar_t* statusText);
    std::wstring firstSelectedRowField(std::initializer_list<std::wstring> fieldNames) const;
    std::wstring firstSelectedRowValue(std::initializer_list<const wchar_t*> fieldNames) const;
    std::wstring selectedRowField(const std::wstring& fieldName) const;
    void clearResultTable();
    void clearResultGridOnly();
    void addResultTableColumn(int index, const std::wstring& title, int width);
    void addResultTableRow(const std::vector<std::wstring>& cells);
    void addResultTableRow(const std::vector<std::wstring>& cells, int indent);
    int currentPrimaryIndex() const;
    int currentSecondaryIndex() const;
    bool currentFeatureUsesVerticalSplitter() const;
    void moveVerticalSplitterFromMouse(int mouseY);

private:
    HWND hwnd_ = nullptr;
    HWND primaryTab_ = nullptr;
    HWND secondaryTab_ = nullptr;
    HWND titleText_ = nullptr;
    HWND summaryText_ = nullptr;
    HWND backendText_ = nullptr;
    HWND statusText_ = nullptr;
    HWND filterLabel_ = nullptr;
    HWND filterEdit_ = nullptr;
    HWND moduleFilterLabel_ = nullptr;
    HWND moduleFilterEdit_ = nullptr;
    HWND symbolicLinkNoteText_ = nullptr;
    HWND deviceDriverDirectoryLabel_ = nullptr;
    HWND deviceDriverDirectoryCombo_ = nullptr;
    HWND deviceDriverTypeLabel_ = nullptr;
    HWND deviceDriverTypeCombo_ = nullptr;
    HWND baseNamedScopeCombo_ = nullptr;
    HWND baseNamedTypeCombo_ = nullptr;
    HWND integrityModuleBaseLabel_ = nullptr;
    HWND integrityModuleBaseEdit_ = nullptr;
    HWND integrityFillFromSelectionButton_ = nullptr;
    HWND integrityCpuOnlyButton_ = nullptr;
    HWND includeCombo_ = nullptr;
    HWND refreshButton_ = nullptr;
    HWND locateButton_ = nullptr;
    HWND copyDiagnosticButton_ = nullptr;
    HWND objectNamespaceTree_ = nullptr;
    int objectNamespaceSelectedRow_ = -1;
    std::wstring objectNamespaceSelectedKind_;
    std::wstring objectNamespaceSelectedPath_;
    std::wstring objectNamespaceSelectedDescription_;
    std::vector<std::unique_ptr<KernelObjectNamespaceTreeNodeState>> objectNamespaceTreeNodeStorage_;
    HWND resultList_ = nullptr;
    HWND propertyList_ = nullptr;
    HWND summaryList_ = nullptr;
    HWND detailEdit_ = nullptr;
    RECT verticalSplitterRect_ = {};
    int verticalSplitterOffset_ = -1;
    bool verticalSplitterDragging_ = false;
    HWND riskOnlyCheck_ = nullptr;
    HWND evidenceIncludeNonModuleCheck_ = nullptr;
    HWND evidenceStartEdit_ = nullptr;
    HWND evidenceEndEdit_ = nullptr;
    HWND evidenceMaxRowsLabel_ = nullptr;
    HWND evidenceMaxRowsEdit_ = nullptr;
    HWND evidenceMaxRowsSpin_ = nullptr;
    HWND integrityIdtVectorsLabel_ = nullptr;
    HWND integrityIdtVectorsEdit_ = nullptr;
    HWND integrityIdtVectorsSpin_ = nullptr;
    HWND callbackGlobalEnabledCheck_ = nullptr;
    HWND callbackApplyButton_ = nullptr;
    HWND callbackReloadButton_ = nullptr;
    HWND callbackImportButton_ = nullptr;
    HWND callbackExportButton_ = nullptr;
    HWND callbackStartReceiverButton_ = nullptr;
    HWND callbackStopReceiverButton_ = nullptr;
    HWND callbackAllowEventButton_ = nullptr;
    HWND callbackDenyEventButton_ = nullptr;
    HWND callbackStatusText_ = nullptr;
    HWND callbackGroupLabel_ = nullptr;
    HWND callbackAddGroupButton_ = nullptr;
    HWND callbackRemoveGroupButton_ = nullptr;
    HWND callbackRenameGroupButton_ = nullptr;
    HWND callbackMoveGroupUpButton_ = nullptr;
    HWND callbackMoveGroupDownButton_ = nullptr;
    HWND callbackGroupList_ = nullptr;
    HWND callbackRuleLabel_ = nullptr;
    HWND callbackAddRuleButton_ = nullptr;
    HWND callbackRemoveRuleButton_ = nullptr;
    HWND callbackMoveRuleUpButton_ = nullptr;
    HWND callbackMoveRuleDownButton_ = nullptr;
    HWND callbackRuleTab_ = nullptr;
    std::vector<HWND> callbackRuleLists_;
    HWND callbackBypassLabel_ = nullptr;
    HWND callbackBypassPidEdit_ = nullptr;
    HWND callbackBypassAddButton_ = nullptr;
    HWND callbackBypassRemoveButton_ = nullptr;
    HWND callbackBypassApplyButton_ = nullptr;
    HWND callbackBypassClearButton_ = nullptr;
    HWND callbackBypassRefreshButton_ = nullptr;
    HWND callbackBypassList_ = nullptr;
    HWND callbackLogTab_ = nullptr;
    HWND callbackAppLogEdit_ = nullptr;
    HWND callbackEventLogEdit_ = nullptr;
    HWND callbackFileMonitorLabel_ = nullptr;
    HWND callbackStartFsctlButton_ = nullptr;
    HWND callbackDrainFileMonitorButton_ = nullptr;
    HWND callbackClearFileMonitorButton_ = nullptr;
    HWND callbackExportFileMonitorButton_ = nullptr;
    HWND callbackFileMonitorFsctlOnlyCheck_ = nullptr;
    HWND callbackFileMonitorStatusText_ = nullptr;
    HWND callbackFileMonitorList_ = nullptr;
    HWND callbackBypassStatusText_ = nullptr;
    std::vector<KernelFeatureDescriptor> features_;
    std::vector<std::wstring> primaryTabs_;
    std::vector<KernelFeatureId> primaryFeatureIds_;
    std::vector<KernelFeatureId> secondaryFeatureIds_;
    KernelFeatureId initialFeatureId_ = KernelFeatureId::kObjectNamespaceOverview;
    bool hasInitialFeatureId_ = false;
    KernelFeatureId directFeatureId_ = KernelFeatureId::kObjectNamespaceOverview;
    bool hasDirectFeatureId_ = false;
    std::vector<std::wstring> currentColumns_;
    std::vector<std::vector<std::wstring>> currentRows_;
    std::vector<int> currentRowIndents_;
    std::vector<std::wstring> collapsedObjectPaths_;
    std::vector<std::wstring> currentRawColumns_;
    std::vector<std::vector<std::wstring>> currentRawRows_;
    struct KernelFeatureViewCache {
        std::vector<std::wstring> columns;
        std::vector<std::vector<std::wstring>> rows;
        std::vector<int> rowIndents;
        std::vector<std::wstring> rawColumns;
        std::vector<std::vector<std::wstring>> rawRows;
        std::vector<std::wstring> collapsedObjectPaths;
        std::vector<std::vector<std::wstring>> propertyRows;
        std::vector<std::vector<std::wstring>> summaryRows;
        std::wstring detailText;
        std::wstring statusText;
        std::wstring filterText;
        std::wstring moduleFilterText;
        int objectNamespaceSelectedRow = -1;
        std::wstring objectNamespaceSelectedKind;
        std::wstring objectNamespaceSelectedPath;
        std::wstring objectNamespaceSelectedDescription;
        int sortColumn = -1;
        bool sortAscending = true;
        int selectedRow = -1;
        int topRow = 0;
        bool hasData = false;
    };
    std::unordered_map<KernelFeatureId, KernelFeatureViewCache> featureViewCache_;
    std::unordered_map<KernelFeatureId, KernelFeatureId> lastSecondaryFeatureByPrimary_;
    KernelFeatureId activeFeatureId_ = KernelFeatureId::kObjectNamespaceOverview;
    bool hasActiveFeatureId_ = false;
    bool suppressFilterChange_ = false;
    KernelFeatureId objectNamespaceTreeFeatureId_ = KernelFeatureId::kObjectNamespaceOverview;
    bool hasObjectNamespaceTreeFeatureId_ = false;
    struct CallbackRuleGroup {
        std::uint32_t id = 0;
        std::wstring name;
        bool enabled = true;
        int priority = 10;
        std::wstring comment;
    };
    struct CallbackRule {
        std::uint32_t id = 0;
        std::uint32_t groupId = 0;
        int typeIndex = 0;
        std::wstring name;
        bool enabled = true;
        std::wstring operation = L"监控";
        std::wstring matchMode = L"包含";
        std::wstring action = L"记录";
        std::uint32_t timeoutMs = 0;
        std::wstring timeoutDefault = L"允许";
        std::wstring initiatorPattern;
        std::wstring targetPattern;
        int priority = 10;
        std::wstring comment;
    };
    std::vector<CallbackRuleGroup> callbackGroups_;
    std::vector<CallbackRule> callbackRules_;
    std::unique_ptr<CallbackEventReceiver> callbackEventReceiver_;
    std::unique_ptr<ksword::ui::AsyncSnapshotTask<KernelOperationResult>> callbackAnswerTask_;
    std::unique_ptr<ksword::ui::AsyncSnapshotTask<CallbackFileIoResult>> callbackFileIoTask_;
    std::unique_ptr<ksword::ui::AsyncSnapshotTask<KernelR0EvidenceSnapshot>> r0EvidenceFilterTask_;
    std::vector<CallbackEventSnapshot> callbackPendingEvents_;
    std::uint32_t nextCallbackGroupId_ = 2;
    std::uint32_t nextCallbackRuleId_ = 1;
    HWND callbackContextList_ = nullptr;
    int contextColumn_ = -1;
    int sortColumn_ = -1;
    bool sortAscending_ = true;
    std::uint64_t queryRequestId_ = 0;
    std::unique_ptr<ksword::ui::AsyncSnapshotTask<KernelOperationResult>> queryTask_;
    std::uint64_t actionRequestId_ = 0;
    std::unique_ptr<ksword::ui::AsyncSnapshotTask<KernelOperationResult>> actionTask_;
    KernelFeatureId pendingR0EvidenceFeatureId_ = KernelFeatureId::kCpuHardwareSnapshot;
    bool hasPendingR0EvidenceFilter_ = false;
    KernelFacade facade_;
};

// createKernelPage creates the Win32-light kernel module page. Inputs are parent,
// command id and bounds; processing allocates a KernelPage owned by its HWND;
// output is the page HWND. The page deletes itself on WM_NCDESTROY.
HWND createKernelPage(HWND parent, int controlId, const RECT& bounds);

// createKernelPageForFeature creates the same Win32-light kernel page but
// preselects one retained kernel feature. Inputs are parent/control/bounds plus
// the stable feature id; output is the page HWND or nullptr on creation failure.
HWND createKernelPageForFeature(HWND parent, int controlId, const RECT& bounds, KernelFeatureId featureId);

} // namespace Ksword::Features::Kernel

#pragma once

#include "ProcessDetailTypes.h"

#include "../../core/Common.h"
#include "../../core/Win32Lean.h"
#include "../../ui/AsyncTask.h"
#include "../../ui/VirtualListView.h"

#include <commctrl.h>

#include "../../../../shared/driver/KswordArkKeyboardIoctl.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

namespace ksword::features::process_detail {

// ProcessDetailPage is the native Win32 conversion of the full process-detail
// layout. It owns native tab pages and does not load foreign UI sources,
// resources, or binaries.
class ProcessDetailPage final {
public:
    static HWND create(
        HWND parent,
        DWORD processId,
        ULONGLONG expectedCreationTime100ns,
        const RECT& bounds);
    static LRESULT CALLBACK windowProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam);

private:
    enum class TabIndex : std::size_t {
        kDetail = 0,
        kThreads,
        kActions,
        kModules,
        kToken,
        kTokenSwitch,
        kEvidence,
        kHotkey,
        kKeyboard,
        kPeb,
        kCount
    };

    enum ControlId : int {
        kTabControl = 1000,

        kDetailTitle = 1100,
        kDetailPath,
        kDetailCopyPath,
        kDetailOpenFolder,
        kDetailCommandLine,
        kDetailCopyCommand,
        kDetailParentText,
        kDetailOpenHandles,
        kDetailGotoParent,
        kDetailStartTime,
        kDetailUser,
        kDetailAdmin,
        kDetailArchitecture,
        kDetailPriority,
        kDetailSession,
        kDetailThreadCount,
        kDetailHandleCount,
        kDetailCpu,
        kDetailRam,
        kDetailDisk,
        kDetailSignature,

        kThreadRefresh = 1200,
        kThreadSample,
        kThreadStack,
        kThreadStatus,
        kThreadList,
        kThreadRuntimeOutput,
        kThreadFilter,

        kActionTerminateMode = 1300,
        kActionTerminate,
        kActionSuspend,
        kActionResume,
        kActionSetCritical,
        kActionClearCritical,
        kActionPriority,
        kActionApplyPriority,
        kActionOpenFolder,
        kActionRefreshPpl,
        kActionEfficiencyOn,
        kActionEfficiencyOff,
        kActionR0Terminate,
        kActionR0Suspend,
        kActionR0Ppl,
        kActionR0Hide,
        kActionR0Danger,
        kActionInjectionMode,
        kActionDllPath,
        kActionBrowseDll,
        kActionInjectDll,
        kActionShellcodePath,
        kActionBrowseShellcode,
        kActionInjectShellcode,
        kActionStatus = 1330,

        kModuleRefresh = 1400,
        kModuleVerifySignature,
        kModuleStatus,
        kModuleList,
        kModuleFilter,

        kTokenRefresh = 1500,
        kTokenStatus,
        kTokenEditorToolbar,
        kTokenCopy,
        kTokenFind,
        kTokenGoto,
        kTokenWrap,
        kTokenOutput,
        kTokenEditorStatus,

        kTokenSwitchRefresh = 1600,
        kTokenSwitchApply,
        kTokenSwitchRefreshAll,
        kTokenSwitchStatus,
        kTokenSandboxInert,
        kTokenVirtualizationAllowed,
        kTokenVirtualizationEnabled,
        kTokenUiAccess,
        kTokenMandatoryNoWriteUp,
        kTokenMandatoryNewProcessMin,
        kTokenHasRestrictions,
        kTokenIsAppContainer,
        kTokenIsRestricted,
        kTokenIsLessPrivilegedAppContainer,
        kTokenIsSandboxed,
        kTokenIsAppSilo,
        kTokenRawInfoClass,
        kTokenRawInputMode,
        kTokenRawPayload,
        kTokenRawApply,

        kEvidenceR0Status = 1700,
        kEvidenceCapability,
        kEvidenceImagePath,
        kEvidenceHandleTable,
        kEvidenceSectionObject,
        kEvidenceProtection,
        kEvidenceSignature,
        kEvidenceSectionSignature,
        kEvidenceSessionSource,
        kEvidenceImagePathSource,
        kEvidenceProtectionSource,
        kEvidenceSignatureSource,
        kEvidenceSectionSignatureSource,
        kEvidenceObjectTableSource,
        kEvidenceSectionObjectSource,
        kEvidenceProtectionOffset,
        kEvidenceSignatureOffset,
        kEvidenceSectionSignatureOffset,
        kEvidenceObjectTableOffset,
        kEvidenceSectionObjectOffset,
        kEvidenceRefreshSection,
        kEvidenceSectionStatus,
        kEvidenceSectionOutput,

        // Process hotkey page controls: unify display of R3 window/menu/resource/shortcut evidence with R0 hotkey evidence.
        kHotkeyRefresh = 1800,
        kHotkeyStatus,
        kHotkeyList,

        // Keyboard page control: Switches between the hotkey table and the WH_KEYBOARD hook chain via internal tabs.
        kKeyboardRefresh = 1900,
        kKeyboardStatus,
        kKeyboardInnerTab,
        kKeyboardList,

        kPebRefresh = 2100,
        kPebApply,
        kPebStatus,
        kPebTarget,
        kPebCommandLine,
        kPebImagePath,
        kPebCurrentDirectory,
        kPebEnvironmentName,
        kPebEnvironmentValue,
        kPebImageBase,
        kPebAffinity,
        kPebPriority,
        kPebOutput,
        kPebReadonlyReason
    };

    struct Placement {
        HWND hwnd = nullptr;
        int x = 0;
        int y = 0;
        int width = 0;  // Negative values mean right margin and stretch.
        int height = 0; // Negative values mean bottom margin and stretch.
    };

    struct PageState {
        HWND hwnd = nullptr;
        std::vector<Placement> placements;
    };

    struct DetailTableFilterResult {
        std::uint64_t sourceGeneration = 0;
        std::wstring query;
        bool useRegex = false;
        int sortColumn = 0;
        bool sortDescending = false;
        std::shared_ptr<const std::vector<ksword::ui::VirtualListRow>> rows;
        std::vector<std::size_t> visibleIndexes;
        HIMAGELIST imageList = nullptr;
    };

    struct ProcessDetailActionResult {
        bool refreshRequired = false;
        bool refreshTokenReport = false;
        bool refreshTokenSwitches = false;
        bool refreshPebReport = false;
        std::wstring statusText;
        std::wstring dialogTitle;
        std::wstring dialogText;
        UINT dialogIcon = 0;
    };

    // ProcessHotkeyEntry stores one line of process hotkey audit results. r0Snapshot is used solely to
    // preserve R0 enumeration evidence; the page never uses kernel addresses as unverified write handles.
    struct ProcessHotkeyEntry {
        std::wstring objectText;
        std::wstring hotkeyText;
        std::wstring processName;
        std::wstring sourceText;
        std::wstring detailText;
        DWORD processId = 0;
        DWORD threadId = 0;
        std::uint32_t hotkeyId = 0;
        std::uint32_t modifiers = 0;
        std::uint32_t virtualKey = 0;
        bool hasR0Snapshot = false;
        KSWORD_ARK_KEYBOARD_HOTKEY_ENTRY r0Snapshot{};
    };

    // ProcessHotkeySnapshot is an immutable result of background hotkey collection; the UI thread only renders
    // the strings and values within it to avoid background tasks holding windows, menus, or COM objects.
    struct ProcessHotkeySnapshot {
        std::vector<ProcessHotkeyEntry> entries;
        std::wstring statusText;
        bool completed = false;
    };

    // KeyboardHookEntry: Stores one line of R0 audit data for a keyboard hook chain; no modification entry provided.
    struct KeyboardHookEntry {
        std::wstring objectText;
        std::wstring typeText;
        std::wstring scopeText;
        std::wstring procedureText;
        std::wstring moduleText;
        std::wstring sourceText;
        std::wstring flagsText;
        std::wstring detailText;
        DWORD processId = 0;
        DWORD threadId = 0;
    };

    // KeyboardSnapshot submits the hotkey table and keyboard hook chain to the keyboard page
    // atomically to prevent mixing two related evidence tables across different refresh generations.
    struct KeyboardSnapshot {
        std::vector<ProcessHotkeyEntry> hotkeys;
        std::vector<KeyboardHookEntry> hooks;
        std::wstring statusText;
        bool completed = false;
    };

    ProcessDetailPage(DWORD processId, ULONGLONG expectedCreationTime100ns);
    ~ProcessDetailPage();

    ProcessDetailPage(const ProcessDetailPage&) = delete;
    ProcessDetailPage& operator=(const ProcessDetailPage&) = delete;

    LRESULT handleMessage(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam);
    static LRESULT CALLBACK pageSubclassProc(
        HWND hwnd,
        UINT message,
        WPARAM wParam,
        LPARAM lParam,
        UINT_PTR subclassId,
        DWORD_PTR referenceData);
    LRESULT handlePageMessage(TabIndex tab, HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam);

    bool initialize(HWND hwnd);
    void layout();
    void layoutPage(TabIndex tab);
    void updateVisiblePage();
    bool ensurePage(TabIndex tab);
    bool createPageHost(TabIndex tab);
    void destroyPageHost(TabIndex tab);
    bool createTabControls(TabIndex tab);
    void populateTab(TabIndex tab);
    void resetTabRuntimeState(TabIndex tab);
    void redrawTabClient();
    void onTabActivated(TabIndex tab);
    void refreshAll();
    void beginSnapshotRefresh(const std::wstring& loadingMessage = L"正在后台加载进程详情…");
    void applySnapshot(ProcessDetailSnapshot snapshot);
    void setSnapshotRefreshControlsEnabled(bool enabled);
    static bool openVerifiedProcessActionTarget(
        DWORD targetProcessId,
        ULONGLONG expectedProcessCreationTime100ns,
        DWORD requestedProcessAccess,
        ksword::core::UniqueHandle& processOut,
        std::wstring& errorText);
    static bool openVerifiedThreadActionTarget(
        DWORD targetProcessId,
        ULONGLONG expectedProcessCreationTime100ns,
        DWORD targetThreadId,
        ULONGLONG expectedThreadCreationTime100ns,
        DWORD requestedThreadAccess,
        ksword::core::UniqueHandle& processOut,
        ksword::core::UniqueHandle& threadOut,
        std::wstring& errorText);
    static bool terminateAllThreadsIfProcessIdentityMatches(
        DWORD targetProcessId,
        ULONGLONG expectedProcessCreationTime100ns,
        std::wstring& detail);

    bool createDetailTab();
    bool createThreadTab();
    bool createActionTab();
    bool createModuleTab();
    bool createTokenTab();
    bool createTokenSwitchTab();
    bool createEvidenceTab();
    bool createHotkeyTab();
    bool createKeyboardTab();
    bool createPebTab();

    HWND addControl(
        TabIndex tab,
        DWORD exStyle,
        const wchar_t* className,
        const wchar_t* text,
        DWORD style,
        int controlId,
        int x,
        int y,
        int width,
        int height);
    HWND addLabel(TabIndex tab, int controlId, const wchar_t* text, int x, int y, int width, int height);
    HWND addButton(TabIndex tab, int controlId, const wchar_t* text, int x, int y, int width, int height);
    HWND addEdit(TabIndex tab, int controlId, const wchar_t* text, bool readOnly, bool multiline, int x, int y, int width, int height);
    HWND addCombo(TabIndex tab, int controlId, int x, int y, int width, int height);
    HWND addCheck(TabIndex tab, int controlId, const wchar_t* text, int x, int y, int width, int height);
    HWND addGroup(TabIndex tab, const wchar_t* text, int x, int y, int width, int height);
    HWND addList(TabIndex tab, int controlId, int x, int y, int width, int height);
    HWND addVirtualList(
        TabIndex tab,
        int controlId,
        int x,
        int y,
        int width,
        int height,
        ksword::ui::VirtualListView& virtualList);
    HWND findControl(TabIndex tab, int controlId) const;
    void setControlText(TabIndex tab, int controlId, const std::wstring& text);
    std::wstring controlText(TabIndex tab, int controlId) const;
    void setPageStatus(TabIndex tab, int controlId, const std::wstring& text);

    static void addListColumn(HWND list, int index, const wchar_t* title, int width);
    static void clearList(HWND list);
    static void addListRow(HWND list, int row, const std::vector<std::wstring>& values, LPARAM data = 0);
    static std::wstring listCell(HWND list, int row, int column);
    static bool copyText(HWND owner, const std::wstring& text);
    static std::wstring readWindowText(HWND hwnd);
    static void applyFont(HWND hwnd, HFONT font = nullptr);

    bool handleGenericContextMenu(HWND source, POINT screenPoint);
    bool handleThreadContextMenu(POINT screenPoint);
    bool handleModuleContextMenu(POINT screenPoint);
    void showModuleDetailDialog();
    void copyListCell(HWND list);
    void copyListRow(HWND list);
    void copyListAll(HWND list);
    int selectedListRow(HWND list) const;

    void populateDetailTab();
    void populateThreadTab();
    void populateModuleTab();
    void populateTokenTab();
    void populateTokenSwitchTab();
    void populateEvidenceTab();
    void populateHotkeyTab();
    void populateKeyboardTab();
    void populatePebTab();
    void requestThreadFilter(bool rebuildRows);
    void requestModuleFilter(bool rebuildRows);
    void executeBackgroundAction(
        TabIndex tab,
        int statusControlId,
        const std::wstring& workingText,
        std::function<ProcessDetailActionResult()> work);
    void setBackgroundActionControlsEnabled(bool enabled);
    void onModuleSortRequested(int column);
    static LRESULT CALLBACK moduleHeaderSubclassProc(
        HWND hwnd,
        UINT message,
        WPARAM wParam,
        LPARAM lParam,
        UINT_PTR subclassId,
        DWORD_PTR referenceData);

    const std::vector<ProcessThreadInfo>& threadEntries() const noexcept;
    const std::vector<ProcessModuleInfo>& moduleEntries() const noexcept;
    std::size_t latestThreadCount() const noexcept;

    bool handleDetailCommand(int controlId);
    bool handleThreadCommand(int controlId);
    bool handleActionCommand(int controlId);
    bool handleModuleCommand(int controlId);
    bool handleTokenCommand(int controlId);
    bool handleTokenSwitchCommand(int controlId);
    bool handleEvidenceCommand(int controlId);
    bool handleHotkeyCommand(int controlId);
    bool handleKeyboardCommand(int controlId);
    bool handlePebCommand(int controlId);
    bool handlePageNotify(TabIndex tab, NMHDR* header, LRESULT& result);

    void suspendSelectedThread();
    void resumeSelectedThread();
    void terminateSelectedThread();
    void terminateSelectedThreadByR0();
    void showSelectedThreadSummary();
    void openSelectedModuleFolder();
    void unloadSelectedModule();
    void suspendSelectedModuleThread();
    void resumeSelectedModuleThread();
    void terminateSelectedModuleThread();
    void executeProcessAction(int actionId);
    void browseForPayload(bool dllMode);
    void applyTokenSwitches();
    void applyRawTokenValue();
    void refreshTokenReport();
    void refreshTokenSwitches();
    void refreshSectionReport();
    void renderSectionReport();
    void refreshPebReport();
    void applyPebEdits();
    void refreshHotkeys();
    void refreshKeyboard();
    void rebuildHotkeyList();
    void rebuildKeyboardList();

private:
    DWORD processId_ = 0;
    ULONGLONG expectedCreationTime100ns_ = 0;
    HWND hwnd_ = nullptr;
    HWND tab_ = nullptr;
    HWND loadingOverlay_ = nullptr;
    HFONT titleFont_ = nullptr;
    TabIndex currentTab_ = TabIndex::kCount;
    std::array<PageState, static_cast<std::size_t>(TabIndex::kCount)> pages_{};
    std::unordered_map<HWND, int> listColumnCounts_;
    std::unordered_map<HWND, int> listContextColumns_;
    ProcessDetailSnapshot snapshot_{};
    std::unique_ptr<ksword::ui::AsyncSnapshotTask<ProcessDetailSnapshot>> snapshotTask_;
    std::unique_ptr<ksword::ui::AsyncSnapshotTask<ProcessDetailActionResult>> actionTask_;
    std::unique_ptr<ksword::ui::AsyncSnapshotTask<ProcessTokenReportSnapshot>> tokenReportTask_;
    std::unique_ptr<ksword::ui::AsyncSnapshotTask<ProcessTokenSwitchSnapshot>> tokenSwitchTask_;
    std::unique_ptr<ksword::ui::AsyncSnapshotTask<ProcessDetailSnapshot>> evidenceTask_;
    std::unique_ptr<ksword::ui::AsyncSnapshotTask<ProcessPebSnapshot>> pebTask_;
    std::unique_ptr<ksword::ui::AsyncSnapshotTask<ProcessHotkeySnapshot>> hotkeyTask_;
    std::unique_ptr<ksword::ui::AsyncSnapshotTask<KeyboardSnapshot>> keyboardTask_;
    std::unique_ptr<ksword::ui::AsyncSnapshotTask<DetailTableFilterResult>> threadFilterTask_;
    std::unique_ptr<ksword::ui::AsyncSnapshotTask<DetailTableFilterResult>> moduleFilterTask_;
    ksword::ui::VirtualListView threadVirtualList_;
    ksword::ui::VirtualListView moduleVirtualList_;
    std::shared_ptr<const std::vector<ProcessThreadInfo>> threadEntries_;
    std::shared_ptr<const std::vector<ProcessThreadInfo>> pendingThreadEntries_;
    std::shared_ptr<const std::vector<ProcessModuleInfo>> moduleEntries_;
    std::shared_ptr<const std::vector<ProcessModuleInfo>> pendingModuleEntries_;
    std::shared_ptr<const std::vector<ksword::ui::VirtualListRow>> threadFilterRows_;
    std::shared_ptr<const std::vector<ksword::ui::VirtualListRow>> moduleFilterRows_;
    std::vector<std::size_t> threadVisibleIndexes_;
    std::vector<std::size_t> moduleVisibleIndexes_;
    std::uint64_t threadSourceGeneration_ = 0;
    std::uint64_t moduleSourceGeneration_ = 0;
    std::wstring threadFilterQuery_;
    bool threadFilterUseRegex_ = false;
    std::wstring moduleFilterQuery_;
    bool moduleFilterUseRegex_ = false;
    int moduleSortColumn_ = 0;
    bool moduleSortDescending_ = false;
    bool moduleVerifySignatures_ = true;
    bool tokenLoaded_ = false;
    bool tokenSwitchLoaded_ = false;
    bool sectionLoaded_ = false;
    bool hotkeyLoaded_ = false;
    bool keyboardLoaded_ = false;
    bool pebLoaded_ = false;
    std::vector<ProcessHotkeyEntry> hotkeyEntries_;
    std::vector<ProcessHotkeyEntry> keyboardHotkeyEntries_;
    std::vector<KeyboardHookEntry> keyboardHookEntries_;
};

} // namespace Ksword::Features::process_detail

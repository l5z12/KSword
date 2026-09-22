#include "ProcessView.h"

#include "ProcessActions.h"
#include "ProcessColumns.h"
#include "ProcessEnumerator.h"
#include "ProcessModel.h"
#include "../audit_common/AuditFormatting.h"
#include "../process_detail/ProcessDetailFeature.h"
#include "../../ui/Controls.h"
#include "../../ui/AsyncTask.h"
#include "../../ui/EntityNavigation.h"
#include "../../ui/ExportUtil.h"
#include "../../ui/FilterBar.h"
#include "../../ui/ListViewUtil.h"
#include "../../ui/Theme.h"
#include "../../ui/VirtualListView.h"
#include "../../../../shared/ark_client/ArkDriverClient.h"
#include "../../../../shared/platform/process/Process.h"

#include <commctrl.h>
#include <commdlg.h>
#include <shellapi.h>
#include <windowsx.h>

#include <algorithm>
#include <atomic>
#include <cstring>
#include <memory>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace ksword::features::process {
namespace {

constexpr wchar_t kProcessViewClass[] = L"KswordARKLight.ProcessView";
constexpr int kRefreshButtonId = 52001;
constexpr int kPresetComboId = 52002;
constexpr int kColumnsButtonId = 52011;
constexpr int kPresetButtonId = 52012;
constexpr int kPauseButtonId = 52003;
constexpr int kPickerButtonId = 52004;
constexpr int kStatusTextId = 52005;
constexpr int kProcessListId = 52006;
constexpr int kRefreshSliderId = 52007;
constexpr int kFilterBarId = 52010;
constexpr UINT kContextMenuBaseId = 53000;
constexpr UINT kColumnMenuBaseId = 54000;
constexpr int kColumnChooserApplyId = 54080;
constexpr int kColumnChooserCancelId = 54081;
constexpr wchar_t kColumnChooserClass[] = L"KswordARKLight.ProcessColumnChooser";
constexpr UINT_PTR kRefreshTimerId = 52008;
constexpr UINT kMsgInitialRefresh = WM_APP + 520;
constexpr UINT kMsgRequestRefresh = WM_APP + 521;
constexpr UINT kMsgRefreshCompleted = WM_APP + 522;
constexpr UINT kMsgFilterCompleted = WM_APP + 523;
constexpr UINT kMsgActionCompleted = WM_APP + 524;
constexpr UINT kMsgOpenDetails = WM_APP + 525;
constexpr int kTreeIndentPixels = 18;
constexpr int kTreeIconGap = 4;
constexpr int kTreeTextGap = 4;

struct NotifyResult {
    bool handled = false;
    LRESULT result = 0;
};

// processStableKey names one snapshot process instance rather than a recyclable PID.
// A zero creation time remains explicit for kernel-only evidence rows.
std::wstring processStableKey(const DWORD processId, const ULONGLONG creationTime100ns) {
    return L"pid:" + std::to_wstring(processId) + L"#" + std::to_wstring(creationTime100ns);
}
// ProcessPresentationRow is the immutable UI snapshot for one process row.
// Keeping display text, identity and icon input together means owner-data
// callbacks never enumerate processes or format every row during a repaint.
struct ProcessPresentationRow {
    ProcessDisplayRow display;
    std::wstring stableKey;
    std::wstring iconPath;
    std::vector<std::wstring> cells;
    DWORD processId = 0;
    ULONGLONG creationTime100ns = 0;
    bool kernelOnly = false;
};

// ProcessFilterResult is produced from a copied presentation snapshot. The UI
// accepts it only when its display generation still matches the current list.
struct ProcessFilterResult {
    std::uint64_t displayGeneration = 0;
    std::wstring query;
    bool useRegex = false;
    std::vector<std::size_t> visibleIndexes;
    std::vector<std::wstring> selectedStableKeys;
    std::wstring topStableKey;
};

// ProcessViewActionResult crosses the worker/UI boundary for a context-menu
// operation. The worker owns only immutable process identity and row snapshots;
// the UI owns status, diagnostics and any follow-up refresh.
struct ProcessViewActionResult {
    ProcessActionResult result;
    bool refreshRequired = false;
};

struct ExternalDetailRequest final {
    DWORD processId = 0;
    ULONGLONG expectedCreationTime100ns = 0;
};

enum class ProcessRowVisualState {
    kNormal,
    kKernelOnly,
    kAdded,
    kRemoved
};


// DetailHostState owns one top-level process detail window. Input values are
// supplied at creation time through CREATESTRUCTW; processing hosts the existing
// WS_CHILD ProcessDetailPage and resizes it with the frame; no value is returned
// directly because lifetime is tied to WM_NCDESTROY.
struct DetailHostState {
    DWORD processId = 0;
    ULONGLONG expectedCreationTime100ns = 0;
    HWND child = nullptr;
    int maximumWidth = 0;
};

struct DetailHostCreateParams {
    DWORD processId = 0;
    ULONGLONG expectedCreationTime100ns = 0;
    int maximumWidth = 0;
};

constexpr wchar_t kProcessDetailHostClass[] = L"KswordARKLight.ProcessDetailHost";

bool ensureDetailChild(HWND hwnd, DetailHostState& state) {
    if (state.child) {
        return true;
    }

    RECT client{};
    ::GetClientRect(hwnd, &client);
    state.child = ksword::features::process_detail::createProcessDetailPage(
        hwnd,
        state.processId,
        state.expectedCreationTime100ns,
        client);
    if (!state.child) {
        return false;
    }
    ::ShowWindow(state.child, SW_SHOW);
    ::MoveWindow(state.child, 0, 0, client.right - client.left, client.bottom - client.top, TRUE);
    return true;
}

// detailHostProc is the top-level process-detail host window procedure. Inputs
// are ordinary Win32 messages; processing creates/resizes the child detail page;
// output is the message LRESULT expected by DefWindowProcW callers.
LRESULT CALLBACK detailHostProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    DetailHostState* state = reinterpret_cast<DetailHostState*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    switch (msg) {
    case WM_NCCREATE: {
        const auto* create = reinterpret_cast<const CREATESTRUCTW*>(lParam);
        const auto* parameters = create ? static_cast<const DetailHostCreateParams*>(create->lpCreateParams) : nullptr;
        auto* owned = new DetailHostState();
        if (parameters) {
            owned->processId = parameters->processId;
            owned->expectedCreationTime100ns = parameters->expectedCreationTime100ns;
            owned->maximumWidth = parameters->maximumWidth;
        }
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(owned));
        return TRUE;
    }
    case WM_CREATE:
        state = reinterpret_cast<DetailHostState*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
        // Delay child-page creation until the first size/show pass. At WM_CREATE
        // the overlapped frame may not yet have its final client rectangle.
        return 0;
    case WM_SIZE:
        if (state && ensureDetailChild(hwnd, *state)) {
            RECT rc{};
            ::GetClientRect(hwnd, &rc);
            ::MoveWindow(state->child, 0, 0, rc.right - rc.left, rc.bottom - rc.top, TRUE);
        }
        return 0;
    case WM_SHOWWINDOW:
        if (state && wParam != FALSE) {
            ensureDetailChild(hwnd, *state);
        }
        return 0;
    case WM_GETMINMAXINFO:
        if (state && state->maximumWidth > 0) {
            auto* minMax = reinterpret_cast<MINMAXINFO*>(lParam);
            minMax->ptMaxTrackSize.x = state->maximumWidth;
        }
        return 0;
    case WM_NCDESTROY:
        delete state;
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
        return 0;
    default:
        break;
    }
    return ::DefWindowProcW(hwnd, msg, wParam, lParam);
}

// registerDetailHostClass installs the standalone detail host class once. There
// is no input; processing registers a standard overlapped window; output reports
// whether CreateWindowExW may use the class name.
bool registerDetailHostClass() {
    static bool registered = false;
    if (registered) {
        return true;
    }

    WNDCLASSW wc{};
    wc.lpfnWndProc = detailHostProc;
    wc.hInstance = ::GetModuleHandleW(nullptr);
    wc.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
    wc.lpszClassName = kProcessDetailHostClass;
    if (::RegisterClassW(&wc) || ::GetLastError() == ERROR_CLASS_ALREADY_EXISTS) {
        registered = true;
    }
    return registered;
}

// openProcessDetailWindow creates one top-level detail window for a single PID.
// Inputs are owner and pid; processing reuses the process_detail page exactly as
// used in docks; output reports whether the host window was created and shown.
bool openProcessDetailWindow(HWND owner, DWORD processId, ULONGLONG expectedCreationTime100ns) {
    if (processId == 0 || expectedCreationTime100ns == 0U || !registerDetailHostClass()) {
        return false;
    }

    const HWND kRootOwner = owner ? ::GetAncestor(owner, GA_ROOT) : nullptr;
    RECT available{};
    if (kRootOwner) {
        ::GetClientRect(kRootOwner, &available);
    }
    int availableWidth = available.right - available.left;
    if (availableWidth <= 0) {
        ::SystemParametersInfoW(SPI_GETWORKAREA, 0, &available, 0);
        availableWidth = available.right - available.left;
    }
    const int kMaximumWidth = std::max(720, availableWidth * 3 / 4);
    const int kInitialWidth = std::min(1160, kMaximumWidth);

    std::wstring processName = leafName(queryProcessImagePath(processId));
    if (processName.empty()) {
        processName = L"<unknown>";
    }
    const std::wstring kTitle = L"进程详细信息 - " + processName + L" (PID " + std::to_wstring(processId) + L")";
    const DetailHostCreateParams kParameters{ processId, expectedCreationTime100ns, kMaximumWidth };
    HWND host = ::CreateWindowExW(WS_EX_APPWINDOW,
        kProcessDetailHostClass,
        kTitle.c_str(),
        WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN | WS_CLIPSIBLINGS,
        CW_USEDEFAULT,
        CW_USEDEFAULT,
        kInitialWidth,
        760,
        kRootOwner,
        nullptr,
        ::GetModuleHandleW(nullptr),
        const_cast<DetailHostCreateParams*>(&kParameters));
    if (!host) {
        return false;
    }

    ::ShowWindow(host, SW_SHOWNORMAL);
    ::UpdateWindow(host);
    auto* state = reinterpret_cast<DetailHostState*>(::GetWindowLongPtrW(host, GWLP_USERDATA));
    if (!state || !ensureDetailChild(host, *state)) {
        ::DestroyWindow(host);
        return false;
    }
    return true;
}

// ProcessViewState owns the controls and model for one process-list page.
// Inputs are Win32 messages routed through processViewWndProc. Processing keeps
// the current snapshot, visible mode, icon cache, picker state, and selected
// rows in sync. Return values are produced by WndProc message handling.
struct ProcessViewState {
    HWND hwnd = nullptr;
    HWND refreshButton = nullptr;
    HWND presetCombo = nullptr;
    HWND columnsButton = nullptr;
    HWND presetButton = nullptr;
    HWND pauseButton = nullptr;
    HWND pickerButton = nullptr;
    HWND refreshSlider = nullptr;
    HWND statusText = nullptr;
    HWND filterBar = nullptr;
    HWND listView = nullptr;
    HIMAGELIST imageList = nullptr;
    ProcessModel model;
    // activeColumns usage: logical columns actually displayed at runtime; not persisted after the page is closed.
    std::vector<ProcessColumnId> activeColumns = defaultProcessColumns(ProcessViewPreset::kMonitor);
    ProcessViewPreset preset = ProcessViewPreset::kMonitor;
    bool pickingWindow = false;
    bool refreshPaused = false;
    UINT refreshIntervalSeconds = 2;
    ULONGLONG previousSampleTickMs = 0;
    std::vector<ProcessActionMenuItem> activeMenuItems;
    std::unordered_map<std::wstring, int> iconCache;
    std::unordered_map<std::wstring, ULONGLONG> previousCpuTime100ns;
    std::unordered_map<std::wstring, ProcessSnapshotRow> lastActiveRowsByIdentity;
    std::unordered_map<std::wstring, ProcessRowVisualState> visualStateByIdentity;
    std::vector<ProcessPresentationRow> presentationRows;
    std::shared_ptr<const std::vector<ksword::ui::VirtualListRow>> filterRows;
    std::vector<std::size_t> visibleRowIndexes;
    std::wstring displayTextScratch;
    std::wstring filterQuery;
    bool filterUseRegex = false;
    std::uint64_t displayGeneration = 0;
    bool hasLastActiveSnapshot = false;
    std::unique_ptr<ksword::ui::AsyncSnapshotTask<struct ProcessRefreshSnapshot>> refreshTask;
    std::unique_ptr<ksword::ui::AsyncSnapshotTask<ProcessFilterResult>> filterTask;
    std::unique_ptr<ksword::ui::AsyncSnapshotTask<ProcessViewActionResult>> actionTask;
};

ULONGLONG resolveCurrentProcessCreationTime(
    const ProcessViewState& state,
    const DWORD processId,
    const ULONGLONG expectedCreationTime100ns) {
    for (const ProcessSnapshotRow& row : state.model.rows()) {
        if (row.processId != processId) {
            continue;
        }
        if (expectedCreationTime100ns != 0U && row.creationTime100ns != expectedCreationTime100ns) {
            return 0U;
        }
        if (row.creationTime100ns != 0U) {
            return row.creationTime100ns;
        }
    }

    HANDLE process = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
    if (!process) {
        return 0U;
    }
    FILETIME creation{};
    FILETIME exit{};
    FILETIME kernel{};
    FILETIME user{};
    ULARGE_INTEGER value{};
    if (::GetProcessTimes(process, &creation, &exit, &kernel, &user)) {
        value.LowPart = creation.dwLowDateTime;
        value.HighPart = creation.dwHighDateTime;
    }
    ::CloseHandle(process);
    if (expectedCreationTime100ns != 0U && value.QuadPart != expectedCreationTime100ns) {
        return 0U;
    }
    return value.QuadPart;
}

// KernelProcessSnapshotEntry purpose: stores one row of process evidence returned by ArkDriverClient R0 enumeration.
// Invocation: enumerateProcessesByR0Driver populates, applyDefaultHiddenProcessAudit merges into R3 rows.
struct KernelProcessSnapshotEntry {
    std::uint32_t processId = 0;
    std::uint32_t parentProcessId = 0;
    std::uint32_t flags = 0;
    std::uint32_t sessionId = 0;
    std::uint32_t fieldFlags = 0;
    std::uint32_t r0Status = KSWORD_ARK_PROCESS_R0_STATUS_UNAVAILABLE;
    std::uint8_t protection = 0;
    std::uint32_t protectionSource = KSWORD_ARK_PROCESS_FIELD_SOURCE_UNAVAILABLE;
    std::uint64_t objectTableAddress = 0;
    std::uint64_t sectionObjectAddress = 0;
    std::string imageName;
    std::string imagePath;
};

// HiddenProcessAuditResult purpose: Aggregate default R0 hidden process enumeration results and append them to the status bar.
// Return value semantics: querySucceeded=false indicates the driver is unavailable or the IOCTL failed, but the standard R3 refresh continues execution.
struct HiddenProcessAuditResult {
    bool querySucceeded = false;
    std::size_t kernelEnumeratedCount = 0;
    std::size_t kernelOnlyCount = 0;
    std::wstring detailText;
};

// ProcessRefreshSnapshot is produced entirely on a worker thread. It keeps R3
// enumeration and both R0 evidence queries out of timer and button handlers.
struct ProcessRefreshSnapshot {
    ProcessEnumerationResult enumeration;
    HiddenProcessAuditResult hiddenAudit;
    std::wstring crossViewStatusSuffix;
};

// activeColumnSet purpose: Convert the logical column set into physical column descriptions for the current ListView.
std::vector<ksword::ui::ListViewColumn> activeColumnSet(const ProcessViewState& state) {
    std::vector<ksword::ui::ListViewColumn> columns;
    columns.reserve(state.activeColumns.size());
    for (std::size_t index = 0; index < state.activeColumns.size(); ++index) {
        const ProcessColumnDescriptor* descriptor = findProcessColumn(state.activeColumns[index]);
        if (descriptor) columns.push_back({ static_cast<int>(index), descriptor->width, descriptor->format, descriptor->title });
    }
    return columns;
}

// stateFromWindow returns the state pointer stored on the page HWND. Input is a
// window handle; processing reads GWLP_USERDATA; output is null before creation
// finishes or after destruction clears the pointer.
ProcessViewState* stateFromWindow(HWND hwnd) {
    return reinterpret_cast<ProcessViewState*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
}

// setStatus writes a short human-readable status line. Inputs are page state and
// text; processing updates the STATIC control; no value is returned.
void setStatus(ProcessViewState& state, const std::wstring& text) {
    if (state.statusText) {
        ::SetWindowTextW(state.statusText, text.c_str());
    }
}

// refreshIntervalMs returns the active refresh period in milliseconds. Input is
// state.refreshIntervalSeconds from the compact slider; processing clamps the
// value to the supported slider range; output is passed to SetTimer.
UINT refreshIntervalMs(const ProcessViewState& state) {
    const UINT kSeconds = std::clamp<UINT>(state.refreshIntervalSeconds, 1, 10);
    return kSeconds * 1000U;
}

// restartRefreshTimer applies the current slider interval to the page timer.
// Input is the process page state; processing kills the old timer and creates a
// new one on the page HWND; no value is returned.
void restartRefreshTimer(ProcessViewState& state) {
    if (!state.hwnd) {
        return;
    }
    ::KillTimer(state.hwnd, kRefreshTimerId);
    ::SetTimer(state.hwnd, kRefreshTimerId, refreshIntervalMs(state), nullptr);
}

// updateToolbarTexts keeps compact button labels in sync with runtime state.
// Input is the page state; processing updates only existing HWNDs; no value is
// returned because controls may be absent during partial creation.
void updateToolbarTexts(ProcessViewState& state) {
    if (state.presetCombo) {
        const LRESULT kCount = ::SendMessageW(state.presetCombo, CB_GETCOUNT, 0, 0);
        for (LRESULT index = 0; index < kCount; ++index) {
            if (static_cast<ProcessViewPreset>(::SendMessageW(state.presetCombo, CB_GETITEMDATA, index, 0)) == state.preset) {
                ::SendMessageW(state.presetCombo, CB_SETCURSEL, index, 0);
                break;
            }
        }
    }
    if (state.pauseButton) {
        ::SetWindowTextW(state.pauseButton, state.refreshPaused ? L"恢复" : L"暂停");
    }
}

// createProcessListView creates a multi-select report ListView. Inputs are the
// parent HWND and child id. Processing intentionally avoids the shared helper
// because that helper enables LVS_SINGLESEL; output is the child HWND or null.
HWND createProcessListView(HWND parent, int id) {
    HWND hwnd = ::CreateWindowExW(WS_EX_CLIENTEDGE,
        WC_LISTVIEWW,
        L"",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_CLIPSIBLINGS | LVS_REPORT | LVS_SHOWSELALWAYS | LVS_OWNERDATA,
        0,
        0,
        0,
        0,
        parent,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)),
        ::GetModuleHandleW(nullptr),
        nullptr);
    if (!hwnd) {
        return nullptr;
    }

    ::SendMessageW(hwnd, WM_SETFONT, reinterpret_cast<WPARAM>(ksword::ui::systemUiFont()), TRUE);
    ListView_SetExtendedListViewStyleEx(hwnd,
        LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP,
        LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP);
    return hwnd;
}

// createIconList creates the small-image list used by the process list. There
// are no inputs; processing asks comctl32 for a 16x16 image list; output is the
// HIMAGELIST handle or null. The caller owns and destroys it.
HIMAGELIST createIconList() {
    return ImageList_Create(::GetSystemMetrics(SM_CXSMICON),
        ::GetSystemMetrics(SM_CYSMICON),
        ILC_COLOR32 | ILC_MASK,
        64,
        64);
}

// addIconFromShell extracts a small icon for a path or returns a generic icon.
// Inputs are the image list, an executable path and whether fallback is allowed.
// Processing uses SHGetFileInfoW and copies the icon into the image list. Return
// value is the image index or -1 when no icon could be obtained.
int addIconFromShell(HIMAGELIST imageList, const std::wstring& path, bool fallback) {
    if (!imageList) {
        return -1;
    }

    SHFILEINFOW info{};
    UINT flags = SHGFI_ICON | SHGFI_SMALLICON;
    const wchar_t* queryPath = path.empty() ? L".exe" : path.c_str();
    if (path.empty() && fallback) {
        flags |= SHGFI_USEFILEATTRIBUTES;
    }

    if (!::SHGetFileInfoW(queryPath,
            fallback ? FILE_ATTRIBUTE_NORMAL : 0,
            &info,
            sizeof(info),
            flags) || !info.hIcon) {
        return -1;
    }

    const int kIndex = ImageList_AddIcon(imageList, info.hIcon);
    ::DestroyIcon(info.hIcon);
    return kIndex;
}

// iconIndexForPath resolves and caches a process icon. Inputs are page state and
// an executable path. Processing extracts an icon with Shell APIs and caches by
// path; output is a ListView image index, falling back to a generic executable.
int iconIndexForPath(ProcessViewState& state, const std::wstring& path) {
    const std::wstring kKey = path.empty() ? L"<generic-exe>" : path;
    const auto kFound = state.iconCache.find(kKey);
    if (kFound != state.iconCache.end()) {
        return kFound->second;
    }

    int index = addIconFromShell(state.imageList, path, path.empty());
    if (index < 0 && !path.empty()) {
        index = iconIndexForPath(state, std::wstring());
    }
    if (index >= 0) {
        state.iconCache.emplace(kKey, index);
    }
    return index;
}

// layoutChildren positions the toolbar, status text and ListView. Inputs are the
// page state and client rectangle; processing uses fixed toolbar heights and the
// remaining area for process rows; no value is returned.
void layoutChildren(ProcessViewState& state, const RECT& rc) {
    const int kButtonHeight = 24;
    const int kButtonTop = 0;
    int x = 0;

    ::MoveWindow(state.refreshButton, x, kButtonTop, 56, kButtonHeight, TRUE);
    x += 56;
    ::MoveWindow(state.pauseButton, x, kButtonTop, 56, kButtonHeight, TRUE);
    x += 56;
    ::MoveWindow(state.presetCombo, x, kButtonTop, 92, kButtonHeight + 180, TRUE);
    x += 92;
    ::MoveWindow(state.columnsButton, x, kButtonTop, 54, kButtonHeight, TRUE);
    x += 54;
    ::MoveWindow(state.pickerButton, x, kButtonTop, 104, kButtonHeight, TRUE);
    x += 104;
    ::MoveWindow(state.refreshSlider, x, kButtonTop + 2, 110, kButtonHeight - 4, TRUE);
    x += 110;

    const int kStatusTop = kButtonTop + kButtonHeight;
    const int kWidth = std::max(100, static_cast<int>(rc.right - rc.left));
    const int kHeight = std::max(100, static_cast<int>(rc.bottom - rc.top));
    if (state.filterBar) {
        ::MoveWindow(state.filterBar,
            x + 8,
            kButtonTop,
            std::max(1, kWidth - x - 8),
            kButtonHeight,
            TRUE);
    }
    ::MoveWindow(state.statusText, 0, kStatusTop, kWidth, 20, TRUE);

    const int kListTop = kStatusTop + 20;
    ::MoveWindow(state.listView,
        0,
        kListTop,
        std::max(80, kWidth),
        std::max(80, kHeight - kListTop),
        TRUE);
}

// paintBackground clears the page background only. Inputs are HWND and paint DC;
// processing intentionally draws no title text or decorative padding; no value
// is returned.
void paintBackground(HWND hwnd, HDC dc) {
    RECT rc{};
    ::GetClientRect(hwnd, &rc);
    ::FillRect(dc, &rc, ksword::ui::appTheme().windowBrush());
}

// rebuildColumns replaces the ListView columns for the current mode. Input is
// page state; processing deletes old columns and inserts mode-specific headers;
// no value is returned.
void rebuildColumns(ProcessViewState& state) {
    if (!state.listView) {
        return;
    }

    HWND header = ListView_GetHeader(state.listView);
    const int kCount = header ? Header_GetItemCount(header) : 0;
    for (int index = kCount - 1; index >= 0; --index) {
        ListView_DeleteColumn(state.listView, index);
    }

    for (const auto& column : activeColumnSet(state)) {
        LVCOLUMNW nativeColumn{};
        nativeColumn.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_FMT;
        nativeColumn.fmt = column.format;
        nativeColumn.cx = column.width;
        nativeColumn.pszText = const_cast<LPWSTR>(column.title.c_str());
        ListView_InsertColumn(state.listView, column.index, &nativeColumn);
    }
}

// Selection and the filtering scheduler are declared here because installing
// a new immutable presentation must save process-instance selection and viewport
// before replacing the owner-data row count.
std::vector<DWORD> selectedPids(ProcessViewState& state);
std::vector<std::wstring> selectedStableKeys(ProcessViewState& state);
std::wstring stableKeyFromListItem(const ProcessViewState& state, int item);
void applyProcessFilter(ProcessViewState& state,
    ProcessFilterResult result,
    const std::vector<ProcessPresentationRow>* previousPresentationRows = nullptr,
    const std::vector<std::size_t>* previousVisibleRowIndexes = nullptr,
    const std::unordered_map<std::wstring, ProcessRowVisualState>* previousVisualStates = nullptr);
void requestProcessFilter(ProcessViewState& state,
    const std::wstring& query,
    std::vector<std::wstring> selectedStableKeys,
    std::wstring topStableKey);

// buildPresentationRows converts the model into immutable owner-data rows once
// per completed snapshot. Formatting is deliberately not performed by
// LVN_GETDISPINFO or custom draw, keeping scrolling independent of table size.
void buildPresentationRows(ProcessViewState& state,
    std::vector<ProcessPresentationRow>& presentationRows,
    std::vector<ksword::ui::VirtualListRow>& filterRows) {
    const auto& sourceRows = state.model.displayRows(ProcessViewMode::kUtilizationFriendly);
    presentationRows.clear();
    filterRows.clear();
    presentationRows.reserve(sourceRows.size());
    filterRows.reserve(sourceRows.size());

    for (const ProcessDisplayRow& sourceRow : sourceRows) {
        ProcessPresentationRow row{};
        row.display = sourceRow;
        row.cells.reserve(state.activeColumns.size());
        for (const ProcessColumnId kColumn : state.activeColumns) {
            const ProcessSnapshotRow* process = state.model.rowForDisplayRow(sourceRow);
            row.cells.push_back(sourceRow.groupHeader
                ? (kColumn == ProcessColumnId::kName ? sourceRow.title : L"")
                : (process ? processColumnText(*process, kColumn) : L""));
        }

        if (const ProcessSnapshotRow* process = state.model.rowForDisplayRow(sourceRow)) {
            row.processId = process->processId;
            row.creationTime100ns = process->creationTime100ns;
            row.kernelOnly = process->r0KernelOnly;
            row.iconPath = process->imagePath;
            row.stableKey = processStableKey(process->processId, process->creationTime100ns);
        } else {
            row.stableKey = L"group:" + std::to_wstring(static_cast<int>(sourceRow.group));
        }

        ksword::ui::VirtualListRow filterRow{};
        filterRow.stableKey = row.stableKey;
        filterRow.cells = row.cells;
        // Full-column text is used only for filtering and does not alter the visible column layout of the current ListView.
        if (const ProcessSnapshotRow* process = state.model.rowForDisplayRow(sourceRow)) {
            for (const ProcessColumnDescriptor& column : processColumnDescriptors()) {
                filterRow.cells.push_back(processColumnText(*process, column.id));
            }
        }
        if (!row.iconPath.empty()) {
            filterRow.cells.push_back(row.iconPath);
        }

        presentationRows.push_back(std::move(row));
        filterRows.push_back(std::move(filterRow));
    }
}

// rebuildRows creates and installs a complete owner-data snapshot in one UI
// transaction. The previous rows stay mapped until the new filter indexes are
// ready, so periodic refreshes never briefly clear the process list.
void rebuildRows(ProcessViewState& state,
    const std::unordered_map<std::wstring, ProcessRowVisualState>* previousVisualStates = nullptr) {
    if (!state.listView) {
        return;
    }

    const std::vector<std::wstring> kSelectedStableKeys = selectedStableKeys(state);
    const std::wstring kTopStableKey = stableKeyFromListItem(state, ListView_GetTopIndex(state.listView));
    std::vector<ProcessPresentationRow> previousPresentationRows = std::move(state.presentationRows);
    const std::vector<std::size_t> kPreviousVisibleRowIndexes = state.visibleRowIndexes;
    auto filterRows = std::make_shared<std::vector<ksword::ui::VirtualListRow>>();
    buildPresentationRows(state, state.presentationRows, *filterRows);
    state.filterRows = std::move(filterRows);
    ++state.displayGeneration;

    const std::wstring kQuery = state.filterBar ? ksword::ui::getFilterBarText(state.filterBar) : state.filterQuery;
    state.filterQuery = kQuery;
    state.filterUseRegex = ksword::ui::getFilterBarRegexEnabled(state.filterBar);

    // Process snapshots are intentionally kept compact, so matching this
    // immutable text view on the UI thread is cheap. More importantly, it lets
    // the list swap from one valid mapping directly to the next instead of
    // exposing an empty owner-data table while a worker filters the new rows.
    ProcessFilterResult result{};
    result.displayGeneration = state.displayGeneration;
    result.query = kQuery;
    result.useRegex = state.filterUseRegex;
    result.selectedStableKeys = kSelectedStableKeys;
    result.topStableKey = kTopStableKey;
    result.visibleIndexes = ksword::ui::VirtualListView::filterRowIndexes(
        *state.filterRows,
        result.query,
        result.useRegex);
    applyProcessFilter(state,
        std::move(result),
        &previousPresentationRows,
        &kPreviousVisibleRowIndexes,
        previousVisualStates);
}

// displayIndexFromListItem maps a visible owner-data row to its immutable
// presentation index. It does not call ListView_GetItem because owner-data
// controls do not retain one LVITEM per row.
int displayIndexFromListItem(const ProcessViewState& state, int item) {
    if (item < 0 || static_cast<std::size_t>(item) >= state.visibleRowIndexes.size()) {
        return -1;
    }
    const std::size_t kDisplayIndex = state.visibleRowIndexes[static_cast<std::size_t>(item)];
    return kDisplayIndex <= static_cast<std::size_t>(INT_MAX) ? static_cast<int>(kDisplayIndex) : -1;
}

// selectedDisplayIndexes reads the current multi-selection and translates the
// visible owner-data indexes through the immutable result mapping.
std::vector<int> selectedDisplayIndexes(ProcessViewState& state) {
    std::vector<int> indexes;
    if (!state.listView) {
        return indexes;
    }

    int item = -1;
    while ((item = ListView_GetNextItem(state.listView, item, LVNI_SELECTED)) != -1) {
        const int kDisplayIndex = displayIndexFromListItem(state, item);
        if (kDisplayIndex >= 0) {
            indexes.push_back(kDisplayIndex);
        }
    }
    return indexes;
}

// selectedPids converts selected immutable presentation rows to process ids.
// Group headers remain selectable for copy operations but never become actions.
std::vector<DWORD> selectedPids(ProcessViewState& state) {
    std::vector<DWORD> pids;
    for (const int kIndex : selectedDisplayIndexes(state)) {
        if (kIndex < 0 || static_cast<std::size_t>(kIndex) >= state.presentationRows.size()) {
            continue;
        }
        const DWORD kProcessId = state.presentationRows[static_cast<std::size_t>(kIndex)].processId;
        if (kProcessId != 0) {
            pids.push_back(kProcessId);
        }
    }
    return pids;
}

// selectedStableKeys retains only real process rows and preserves their snapshot
// identity across an asynchronous filter/rebuild cycle.
std::vector<std::wstring> selectedStableKeys(ProcessViewState& state) {
    std::vector<std::wstring> stableKeys;
    for (const int kIndex : selectedDisplayIndexes(state)) {
        if (kIndex < 0 || static_cast<std::size_t>(kIndex) >= state.presentationRows.size()) {
            continue;
        }
        const ProcessPresentationRow& row = state.presentationRows[static_cast<std::size_t>(kIndex)];
        if (row.processId != 0 && !row.stableKey.empty()) {
            stableKeys.push_back(row.stableKey);
        }
    }
    return stableKeys;
}

std::wstring stableKeyFromListItem(const ProcessViewState& state, const int item) {
    const int kDisplayIndex = displayIndexFromListItem(state, item);
    if (kDisplayIndex < 0 || static_cast<std::size_t>(kDisplayIndex) >= state.presentationRows.size()) {
        return {};
    }
    return state.presentationRows[static_cast<std::size_t>(kDisplayIndex)].stableKey;
}

// groupHeaderAtListItem returns the clicked friendly group header from the
// current immutable presentation snapshot.
const ProcessPresentationRow* groupHeaderAtListItem(ProcessViewState& state, int item) {
    const int kDisplayIndex = displayIndexFromListItem(state, item);
    if (kDisplayIndex < 0 || static_cast<std::size_t>(kDisplayIndex) >= state.presentationRows.size()) {
        return nullptr;
    }
    const ProcessPresentationRow& row = state.presentationRows[static_cast<std::size_t>(kDisplayIndex)];
    return row.display.groupHeader ? &row : nullptr;
}

// displayRowFromListItem resolves a visible owner-data row without touching the
// model. Custom drawing therefore remains O(visible cells), even for long lists.
const ProcessPresentationRow* displayRowFromListItem(ProcessViewState& state, int item) {
    const int kDisplayIndex = displayIndexFromListItem(state, item);
    if (kDisplayIndex < 0 || static_cast<std::size_t>(kDisplayIndex) >= state.presentationRows.size()) {
        return nullptr;
    }
    return &state.presentationRows[static_cast<std::size_t>(kDisplayIndex)];
}

// visualStateForDisplayRow resolves green/gray lifecycle highlighting for a
// visible process row. Inputs are page state and display row; processing maps
// the process instance stable key into the latest refresh-diff table; output is
// Normal for groups and unchanged process rows.
ProcessRowVisualState visualStateForDisplayRow(ProcessViewState& state, const ProcessPresentationRow& displayRow) {
    if (displayRow.processId == 0) {
        return ProcessRowVisualState::kNormal;
    }
    if (displayRow.display.groupHeader) {
        return ProcessRowVisualState::kNormal;
    }
    if (displayRow.kernelOnly) {
        return ProcessRowVisualState::kKernelOnly;
    }
    const auto kSource = state.visualStateByIdentity.find(displayRow.stableKey);
    return kSource != state.visualStateByIdentity.end() ? kSource->second : ProcessRowVisualState::kNormal;
}

// rowBackgroundColor returns the fill color used by custom draw. Inputs are
// selection and lifecycle state; processing gives selected rows system colors,
// new rows light green and deleted rows light gray; output is a COLORREF.
COLORREF rowBackgroundColor(bool selected, ProcessRowVisualState visualState) {
    if (selected) {
        return ::GetSysColor(COLOR_HIGHLIGHT);
    }
    if (visualState == ProcessRowVisualState::kKernelOnly) {
        return RGB(255, 226, 226);
    }
    if (visualState == ProcessRowVisualState::kAdded) {
        return RGB(216, 248, 216);
    }
    if (visualState == ProcessRowVisualState::kRemoved) {
        return RGB(232, 232, 232);
    }
    return ::GetSysColor(COLOR_WINDOW);
}

// rowTextColor returns the text color used by custom draw. Inputs are selection
// and lifecycle state; processing keeps deleted rows muted while selected rows
// use system highlight text; output is a COLORREF.
COLORREF rowTextColor(bool selected, ProcessRowVisualState visualState) {
    if (selected) {
        return ::GetSysColor(COLOR_HIGHLIGHTTEXT);
    }
    if (visualState == ProcessRowVisualState::kKernelOnly) {
        return RGB(150, 0, 0);
    }
    if (visualState == ProcessRowVisualState::kRemoved) {
        return ::GetSysColor(COLOR_GRAYTEXT);
    }
    return ::GetSysColor(COLOR_WINDOWTEXT);
}

// subItemBounds returns a bounded rectangle for one report-cell. Inputs are the
// list view, item and subitem; processing avoids the common-control quirk where
// subitem zero can report the whole row by clamping to column zero width; output
// is true when a rectangle was obtained.
bool subItemBounds(HWND listView, int item, int subItem, RECT& bounds) {
    bounds = {};
    if (subItem == 0) {
        bounds.left = LVIR_BOUNDS;
        if (!ListView_GetSubItemRect(listView, item, 0, LVIR_BOUNDS, &bounds)) {
            return false;
        }
        bounds.right = bounds.left + ListView_GetColumnWidth(listView, 0);
        return true;
    }
    return ListView_GetSubItemRect(listView, item, subItem, LVIR_BOUNDS, &bounds) != FALSE;
}

// textFormatForColumn maps ListView column alignment into DrawText flags.
// Inputs are the active mode and subitem index; output uses vertical centering,
// ellipsis and the column's left/right alignment.
UINT textFormatForColumn(const ProcessViewState& state, int subItem) {
    UINT format = DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS;
    const auto kColumns = activeColumnSet(state);
    for (const auto& column : kColumns) {
        if (column.index == subItem && column.format == LVCFMT_RIGHT) {
            return format | DT_RIGHT;
        }
    }
    return format | DT_LEFT;
}

// drawDottedTreeGuides paints lightweight dotted indentation guides. Inputs are
// the draw DC, first-column bounds and process depth; processing uses the
// current system text color family with a dotted pen; no value is returned.
void drawDottedTreeGuides(HDC dc, const RECT& bounds, int depth) {
    if (depth <= 0) {
        return;
    }

    HPEN pen = ::CreatePen(PS_DOT, 1, ::GetSysColor(COLOR_3DSHADOW));
    if (!pen) {
        return;
    }
    HGDIOBJ oldPen = ::SelectObject(dc, pen);
    const int kRowMidY = bounds.top + (bounds.bottom - bounds.top) / 2;
    for (int level = 1; level <= depth; ++level) {
        const int kX = bounds.left + (level - 1) * kTreeIndentPixels + kTreeIndentPixels / 2;
        ::MoveToEx(dc, kX, bounds.top, nullptr);
        ::LineTo(dc, kX, bounds.bottom);
    }
    const int kBranchX = bounds.left + (depth - 1) * kTreeIndentPixels + kTreeIndentPixels / 2;
    const int kIconLeft = bounds.left + depth * kTreeIndentPixels;
    ::MoveToEx(dc, kBranchX, kRowMidY, nullptr);
    ::LineTo(dc, kIconLeft, kRowMidY);
    ::SelectObject(dc, oldPen);
    ::DeleteObject(pen);
}

// drawProcessSubItem custom-draws every visible process cell. Inputs are the
// page state and NMLVCUSTOMDRAW payload; processing draws a stable background,
// optional tree guides/icon in column zero, and text for all columns so hover
// repaint never erases row text; output reports whether default drawing should
// be skipped.
LRESULT drawProcessSubItem(ProcessViewState& state, NMLVCUSTOMDRAW* draw) {
    if (!draw) {
        return CDRF_DODEFAULT;
    }

    const int kItem = static_cast<int>(draw->nmcd.dwItemSpec);
    const int kSubItem = draw->iSubItem;
    const ProcessPresentationRow* displayRow = displayRowFromListItem(state, kItem);
    if (!displayRow) {
        return CDRF_DODEFAULT;
    }

    RECT cell{};
    if (!subItemBounds(state.listView, kItem, kSubItem, cell)) {
        return CDRF_DODEFAULT;
    }

    HDC dc = draw->nmcd.hdc;
    const bool kSelected = (ListView_GetItemState(state.listView, kItem, LVIS_SELECTED) & LVIS_SELECTED) != 0;
    const bool kFocused = (ListView_GetItemState(state.listView, kItem, LVIS_FOCUSED) & LVIS_FOCUSED) != 0;
    const ProcessRowVisualState kVisualState = visualStateForDisplayRow(state, *displayRow);
    const COLORREF kBackground = rowBackgroundColor(kSelected, kVisualState);
    const COLORREF kTextColor = rowTextColor(kSelected, kVisualState);
    HBRUSH brush = ::CreateSolidBrush(kBackground);
    if (brush) {
        ::FillRect(dc, &cell, brush);
        ::DeleteObject(brush);
    }

    ::SetBkMode(dc, TRANSPARENT);
    ::SetTextColor(dc, kTextColor);
    HFONT font = ksword::ui::systemUiFont();
    HGDIOBJ oldFont = font ? ::SelectObject(dc, font) : nullptr;

    if (kSubItem == 0 && !displayRow->display.groupHeader) {
        drawDottedTreeGuides(dc, cell, displayRow->display.depth);
        const int kIconSize = ::GetSystemMetrics(SM_CXSMICON);
        const int kIconLeft = cell.left + displayRow->display.depth * kTreeIndentPixels;
        const int kRowHeight = static_cast<int>(cell.bottom - cell.top);
        const int kIconTop = static_cast<int>(cell.top) + std::max(0, (kRowHeight - kIconSize) / 2);
        const int kIconIndex = iconIndexForPath(state, displayRow->iconPath);
        if (state.imageList && kIconIndex >= 0) {
            ImageList_Draw(state.imageList, kIconIndex, dc, kIconLeft, kIconTop, ILD_TRANSPARENT);
        }

        RECT textRect = cell;
        textRect.left = kIconLeft + kIconSize + kTreeIconGap + kTreeTextGap;
        const std::wstring kEmpty;
        const std::wstring& text = displayRow->cells.empty() ? kEmpty : displayRow->cells.front();
        ::DrawTextW(dc, text.c_str(), static_cast<int>(text.size()), &textRect, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
    } else {
        RECT textRect = cell;
        textRect.left += 4;
        textRect.right -= 4;
        const std::wstring kEmpty;
        const std::wstring& text = kSubItem >= 0 && static_cast<std::size_t>(kSubItem) < displayRow->cells.size()
            ? displayRow->cells[static_cast<std::size_t>(kSubItem)]
            : kEmpty;
        ::DrawTextW(dc, text.c_str(), static_cast<int>(text.size()), &textRect, textFormatForColumn(state, kSubItem));
    }

    if (kFocused && kSubItem == 0) {
        RECT focusRect = cell;
        focusRect.right = cell.left;
        HWND header = ListView_GetHeader(state.listView);
        const int kCount = header ? Header_GetItemCount(header) : 0;
        for (int column = 0; column < kCount; ++column) {
            focusRect.right += ListView_GetColumnWidth(state.listView, column);
        }
        ::DrawFocusRect(dc, &focusRect);
    }
    if (oldFont) {
        ::SelectObject(dc, oldFont);
    }
    return CDRF_SKIPDEFAULT;
}

// handleListCustomDraw owns first-column tree drawing while letting comctl32
// render all other cells normally. Inputs are page state and custom-draw data;
// output is the required custom-draw return code for WM_NOTIFY.
LRESULT handleListCustomDraw(ProcessViewState& state, NMLVCUSTOMDRAW* draw) {
    if (!draw) {
        return CDRF_DODEFAULT;
    }
    switch (draw->nmcd.dwDrawStage) {
    case CDDS_PREPAINT:
        return CDRF_NOTIFYITEMDRAW;
    case CDDS_ITEMPREPAINT:
        return CDRF_NOTIFYSUBITEMDRAW;
    case CDDS_ITEMPREPAINT | CDDS_SUBITEM:
        return drawProcessSubItem(state, draw);
    default:
        return CDRF_DODEFAULT;
    }
}

// handleVirtualListDisplayInfo supplies only the text and lParam requested for
// visible owner-data rows. The backing ProcessPresentationRow snapshot owns the
// text for the entire notification, so no temporary process enumeration occurs.
LRESULT handleVirtualListDisplayInfo(ProcessViewState& state, NMLVDISPINFOW* displayInfo) {
    if (!displayInfo) {
        return 0;
    }

    const int kDisplayIndex = displayIndexFromListItem(state, displayInfo->item.iItem);
    if (kDisplayIndex < 0 || static_cast<std::size_t>(kDisplayIndex) >= state.presentationRows.size()) {
        return 0;
    }

    const ProcessPresentationRow& row = state.presentationRows[static_cast<std::size_t>(kDisplayIndex)];
    if ((displayInfo->item.mask & LVIF_TEXT) != 0) {
        const int kSubItem = displayInfo->item.iSubItem;
        state.displayTextScratch = kSubItem >= 0 && static_cast<std::size_t>(kSubItem) < row.cells.size()
            ? row.cells[static_cast<std::size_t>(kSubItem)]
            : std::wstring{};
        displayInfo->item.pszText = state.displayTextScratch.data();
    }
    if ((displayInfo->item.mask & LVIF_PARAM) != 0) {
        displayInfo->item.lParam = static_cast<LPARAM>(kDisplayIndex);
    }
    return 0;
}

// presentationRowsEqual reports whether two owner-data rows can retain the same
// painted ListView item. Tree layout attributes participate because custom draw
// uses them even when the column text happens to be unchanged.
bool presentationRowsEqual(const ProcessPresentationRow& left, const ProcessPresentationRow& right) {
    return left.stableKey == right.stableKey &&
        left.iconPath == right.iconPath &&
        left.cells == right.cells &&
        left.processId == right.processId &&
        left.creationTime100ns == right.creationTime100ns &&
        left.kernelOnly == right.kernelOnly &&
        left.display.groupHeader == right.display.groupHeader &&
        left.display.group == right.display.group &&
        left.display.depth == right.display.depth;
}

// presentationRowAtVisibleItem maps an owner-data item position through a
// supplied snapshot. It is intentionally independent of ProcessViewState so a
// refresh can compare the old and new snapshots before changing ListView state.
const ProcessPresentationRow* presentationRowAtVisibleItem(
    const std::vector<ProcessPresentationRow>& presentationRows,
    const std::vector<std::size_t>& visibleRowIndexes,
    std::size_t item) {
    if (item >= visibleRowIndexes.size()) {
        return nullptr;
    }
    const std::size_t kDisplayIndex = visibleRowIndexes[item];
    return kDisplayIndex < presentationRows.size() ? &presentationRows[kDisplayIndex] : nullptr;
}

// appendRedrawItem accumulates adjacent list positions into the smallest set of
// ListView_RedrawItems calls. Inputs are an item position and mutable ranges;
// processing appends or extends the tail range; no value is returned.
void appendRedrawItem(std::vector<std::pair<int, int>>& ranges, int item) {
    if (item < 0) {
        return;
    }
    if (!ranges.empty() && item <= ranges.back().second + 1) {
        ranges.back().second = std::max(ranges.back().second, item);
        return;
    }
    ranges.emplace_back(item, item);
}

// applyProcessFilter installs a filtered index map while preserving selection
// and the top visible logical row. Refresh callers pass the outgoing snapshot,
// allowing the virtual ListView to repaint only positions whose presentation
// actually changed instead of blanking and invalidating the full table.
void applyProcessFilter(ProcessViewState& state,
    ProcessFilterResult result,
    const std::vector<ProcessPresentationRow>* previousPresentationRows,
    const std::vector<std::size_t>* previousVisibleRowIndexes,
    const std::unordered_map<std::wstring, ProcessRowVisualState>* previousVisualStates) {
    if (!state.listView || result.displayGeneration != state.displayGeneration || result.query != state.filterQuery ||
        result.useRegex != state.filterUseRegex) {
        return;
    }

    const std::vector<ProcessPresentationRow>& oldPresentationRows = previousPresentationRows
        ? *previousPresentationRows
        : state.presentationRows;
    const std::vector<std::size_t>& oldVisibleRowIndexes = previousVisibleRowIndexes
        ? *previousVisibleRowIndexes
        : state.visibleRowIndexes;
    const std::unordered_map<std::wstring, ProcessRowVisualState>* oldVisualStates = previousVisualStates
        ? previousVisualStates
        : &state.visualStateByIdentity;
    const std::size_t kNewItemCount = std::min<std::size_t>(
        result.visibleIndexes.size(),
        static_cast<std::size_t>(INT_MAX));
    const std::size_t kOldItemCount = std::min<std::size_t>(
        oldVisibleRowIndexes.size(),
        static_cast<std::size_t>(INT_MAX));
    const std::size_t kComparableItemCount = std::min(kOldItemCount, kNewItemCount);
    std::vector<std::pair<int, int>> redrawRanges;
    redrawRanges.reserve(8);

    auto visualStateFor = [](const ProcessPresentationRow* row,
                              const std::unordered_map<std::wstring, ProcessRowVisualState>* visualStates) {
        if (!row || row->display.groupHeader || row->processId == 0) {
            return ProcessRowVisualState::kNormal;
        }
        if (row->kernelOnly) {
            return ProcessRowVisualState::kKernelOnly;
        }
        if (!visualStates) {
            return ProcessRowVisualState::kNormal;
        }
        const auto kFound = visualStates->find(row->stableKey);
        return kFound == visualStates->end() ? ProcessRowVisualState::kNormal : kFound->second;
    };

    for (std::size_t item = 0; item < kComparableItemCount; ++item) {
        const ProcessPresentationRow* oldRow = presentationRowAtVisibleItem(
            oldPresentationRows, oldVisibleRowIndexes, item);
        const ProcessPresentationRow* newRow = presentationRowAtVisibleItem(
            state.presentationRows, result.visibleIndexes, item);
        if (!oldRow || !newRow || !presentationRowsEqual(*oldRow, *newRow) ||
            visualStateFor(oldRow, oldVisualStates) != visualStateFor(newRow, &state.visualStateByIdentity)) {
            appendRedrawItem(redrawRanges, static_cast<int>(item));
        }
    }
    for (std::size_t item = kComparableItemCount; item < kNewItemCount; ++item) {
        appendRedrawItem(redrawRanges, static_cast<int>(item));
    }

    std::vector<int> selectedItemsBefore;
    for (int item = -1;
         (item = ListView_GetNextItem(state.listView, item, LVNI_SELECTED)) != -1;) {
        selectedItemsBefore.push_back(item);
    }

    state.visibleRowIndexes = std::move(result.visibleIndexes);
    int topItem = -1;
    int firstSelectedItem = -1;
    {
        // Do not use ScopedListViewRedrawLock here: its balanced full
        // invalidation would undo the delta calculation above. The header is
        // unchanged, so only freeze the body while its mapping and selection
        // are switched together.
        ksword::ui::ScopedWindowRedrawLock redrawLock(state.listView, false);
        if (kOldItemCount != kNewItemCount) {
            ListView_SetItemCountEx(state.listView,
                static_cast<int>(kNewItemCount),
                LVSICF_NOINVALIDATEALL | LVSICF_NOSCROLL);
        }
        ListView_SetItemState(state.listView, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);

        std::unordered_set<std::wstring> selectedSet(
            result.selectedStableKeys.begin(),
            result.selectedStableKeys.end());
        for (std::size_t item = 0; item < kNewItemCount; ++item) {
            const std::size_t kDisplayIndex = state.visibleRowIndexes[item];
            if (kDisplayIndex >= state.presentationRows.size()) {
                continue;
            }
            const ProcessPresentationRow& row = state.presentationRows[kDisplayIndex];
            if (topItem < 0 && !result.topStableKey.empty() && row.stableKey == result.topStableKey) {
                topItem = static_cast<int>(item);
            }
            if (row.processId != 0 && selectedSet.find(row.stableKey) != selectedSet.end()) {
                const int kSelectedItem = static_cast<int>(item);
                ListView_SetItemState(state.listView, kSelectedItem, LVIS_SELECTED, LVIS_SELECTED);
                if (firstSelectedItem < 0) {
                    firstSelectedItem = kSelectedItem;
                }
            }
        }
        if (firstSelectedItem >= 0) {
            ListView_SetItemState(state.listView, firstSelectedItem, LVIS_FOCUSED, LVIS_FOCUSED);
        }
        if (topItem >= 0) {
            ListView_EnsureVisible(state.listView, topItem, FALSE);
        } else if (firstSelectedItem >= 0) {
            ListView_EnsureVisible(state.listView, firstSelectedItem, FALSE);
        }
    }

    // Selection styling can change independently from row text. Repaint the
    // previous and restored selection positions in addition to data deltas.
    for (const auto& range : redrawRanges) {
        ListView_RedrawItems(state.listView, range.first, range.second);
    }
    for (const int kItem : selectedItemsBefore) {
        if (kItem >= 0 && static_cast<std::size_t>(kItem) < kNewItemCount) {
            ListView_RedrawItems(state.listView, kItem, kItem);
        }
    }
    if (firstSelectedItem >= 0) {
        ListView_RedrawItems(state.listView, firstSelectedItem, firstSelectedItem);
    }
    if (kNewItemCount == 0 && kOldItemCount != 0) {
        ::InvalidateRect(state.listView, nullptr, FALSE);
    }
    if (!result.query.empty()) {
        setStatus(state,
            L"筛选结果 " + std::to_wstring(state.visibleRowIndexes.size()) +
            L" / " + std::to_wstring(state.presentationRows.size()) + L" 行。");
    }
}

// requestProcessFilter captures a shared, immutable text snapshot. Repeated
// keystrokes coalesce in AsyncSnapshotTask and its generation check prevents a
// stale background match from overwriting a newer query or process refresh.
void requestProcessFilter(ProcessViewState& state,
    const std::wstring& query,
    std::vector<std::wstring> selectedStableKeys,
    std::wstring topStableKey) {
    state.filterQuery = query;
    state.filterUseRegex = ksword::ui::getFilterBarRegexEnabled(state.filterBar);
    const std::shared_ptr<const std::vector<ksword::ui::VirtualListRow>> kRows = state.filterRows;
    const std::uint64_t kDisplayGeneration = state.displayGeneration;
    const bool kUseRegex = state.filterUseRegex;
    if (!state.filterTask || !kRows) {
        ProcessFilterResult result{};
        result.displayGeneration = kDisplayGeneration;
        result.query = query;
        result.useRegex = kUseRegex;
        result.selectedStableKeys = std::move(selectedStableKeys);
        result.topStableKey = std::move(topStableKey);
        result.visibleIndexes.resize(state.presentationRows.size());
        for (std::size_t index = 0; index < result.visibleIndexes.size(); ++index) {
            result.visibleIndexes[index] = index;
        }
        applyProcessFilter(state, std::move(result));
        return;
    }

    state.filterTask->request(
        [kRows, kDisplayGeneration, kUseRegex, query, selectedStableKeys = std::move(selectedStableKeys), topStableKey = std::move(topStableKey)]() mutable {
            ProcessFilterResult result{};
            result.displayGeneration = kDisplayGeneration;
            result.query = std::move(query);
            result.useRegex = kUseRegex;
            result.selectedStableKeys = std::move(selectedStableKeys);
            result.topStableKey = std::move(topStableKey);
            result.visibleIndexes = ksword::ui::VirtualListView::filterRowIndexes(*kRows, result.query, kUseRegex);
            return result;
        },
        [&state](std::uint64_t, std::optional<ProcessFilterResult>&& result, std::exception_ptr error) {
            if (error || !result.has_value()) {
                setStatus(state, L"进程筛选任务异常结束。已保留当前可见结果。");
                return;
            }
            applyProcessFilter(state, std::move(*result));
        });
}

// selectedRowsAsText builds tab-separated text for selected visible rows. Inputs
// are page state and whether all columns should be copied. Processing reads the
// current model display rows; output is suitable for the clipboard.
std::wstring selectedRowsAsText(ProcessViewState& state, bool allColumns) {
    const auto kIndexes = selectedDisplayIndexes(state);
    std::wstring text;

    for (int index : kIndexes) {
        if (index < 0 || static_cast<std::size_t>(index) >= state.presentationRows.size()) {
            continue;
        }
        const ProcessPresentationRow& row = state.presentationRows[static_cast<std::size_t>(index)];
        const int kMaxColumn = allColumns ? static_cast<int>(row.cells.size()) : std::min<int>(1, static_cast<int>(row.cells.size()));
        for (int column = 0; column < kMaxColumn; ++column) {
            if (column != 0) {
                text += L'\t';
            }
            text += row.cells[static_cast<std::size_t>(column)];
        }
        text += L"\r\n";
    }
    return text;
}

// visibleRowsAsText exports the current owner-data result mapping, allowing the
// context menu to copy every filtered row without selecting or repainting them.
std::wstring visibleRowsAsText(const ProcessViewState& state) {
    std::wstring text;
    for (const std::size_t kDisplayIndex : state.visibleRowIndexes) {
        if (kDisplayIndex >= state.presentationRows.size()) {
            continue;
        }
        const ProcessPresentationRow& row = state.presentationRows[kDisplayIndex];
        for (std::size_t column = 0; column < row.cells.size(); ++column) {
            if (column != 0) {
                text += L'\t';
            }
            text += row.cells[column];
        }
        text += L"\r\n";
    }
    return text;
}

// visibleRowsAsTsv exports the current filtered owner-data mapping together
// with precisely the columns that are currently visible. It intentionally
// reuses the immutable presentation snapshot, so saving evidence neither
// re-enumerates target processes nor requires any additional access rights.
std::wstring visibleRowsAsTsv(const ProcessViewState& state) {
    if (state.visibleRowIndexes.empty()) {
        return {};
    }

    std::vector<std::wstring> headers;
    headers.reserve(state.activeColumns.size());
    for (const ProcessColumnId kColumn : state.activeColumns) {
        const ProcessColumnDescriptor* descriptor = findProcessColumn(kColumn);
        headers.push_back(descriptor ? descriptor->title : L"");
    }

    std::vector<std::vector<std::wstring>> rows;
    rows.reserve(state.visibleRowIndexes.size());
    for (const std::size_t kDisplayIndex : state.visibleRowIndexes) {
        if (kDisplayIndex < state.presentationRows.size()) {
            rows.push_back(state.presentationRows[kDisplayIndex].cells);
        }
    }
    return ksword::features::audit_common::buildTsv(headers, rows);
}

// exportVisibleResults lets an analyst preserve the exact columns and filtered
// rows currently shown in the process list. saveUtf8TextFileWithDialog records
// the completed user-selected export in the evidence session.
void exportVisibleResults(ProcessViewState& state) {
    const std::wstring kText = visibleRowsAsTsv(state);
    if (kText.empty()) {
        setStatus(state, L"没有可导出的可见进程结果。");
        return;
    }

    std::wstring error;
    switch (ksword::ui::saveUtf8TextFileWithDialog(
        state.hwnd,
        L"processes.tsv",
        L"导出可见进程结果",
        L"TSV (*.tsv)\0*.tsv\0All Files (*.*)\0*.*\0",
        L"tsv",
        kText,
        &error)) {
    case ksword::ui::SaveTextFileResult::kSaved:
        setStatus(state, L"可见进程结果已导出为 TSV，并已记录到证据会话。");
        break;
    case ksword::ui::SaveTextFileResult::kCancelled:
        setStatus(state, L"已取消导出可见进程结果。");
        break;
    case ksword::ui::SaveTextFileResult::kFailed:
        setStatus(state, L"导出可见进程结果失败：" + error);
        break;
    }
}

// narrowToWide converts ArkDriverClient diagnostic strings to the native UI
// encoding. Input is UTF-8/ASCII text from the shared wrapper; output is a
// best-effort wide string suitable for status bars and R0 evidence cells.
std::wstring narrowToWide(const std::string& text) {
    if (text.empty()) {
        return {};
    }

    int chars = ::MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0);
    UINT codePage = CP_UTF8;
    if (chars <= 0) {
        codePage = CP_ACP;
        chars = ::MultiByteToWideChar(codePage, 0, text.data(), static_cast<int>(text.size()), nullptr, 0);
    }
    if (chars <= 0) {
        return L"<decode failed>";
    }

    std::wstring wide(static_cast<std::size_t>(chars), L'\0');
    ::MultiByteToWideChar(codePage, 0, text.data(), static_cast<int>(text.size()), wide.data(), chars);
    return wide;
}

// flagHexText formats raw source/anomaly masks without interpreting unsupported
// future bits. Input is a protocol mask; output is stable uppercase hex.
std::wstring flagHexText(ULONG value) {
    std::wostringstream stream;
    stream << L"0x" << std::hex << std::uppercase << value;
    return stream.str();
}

// processR0StatusText: Converts R0 execution status into text readable by the status bar or table.
// Input: statusValue is one of KSWORD_ARK_PROCESS_R0_STATUS_*. Returns a Chinese phrase; unknown values retain the numeric value.
std::wstring processR0StatusText(const std::uint32_t statusValue) {
    switch (statusValue) {
    case KSWORD_ARK_PROCESS_R0_STATUS_OK:
        return L"OK";
    case KSWORD_ARK_PROCESS_R0_STATUS_PARTIAL:
        return L"Partial";
    case KSWORD_ARK_PROCESS_R0_STATUS_DYNDATA_MISSING:
        return L"DynData missing";
    case KSWORD_ARK_PROCESS_R0_STATUS_READ_FAILED:
        return L"Read failed";
    default:
        return L"Unavailable";
    }
}

// enumerateProcessesByR0Driver: Reuses the Ksword5.1 R0 process enumeration method to detect hidden processes.
// The processListOut parameter receives R0 data; detailTextOut receives ArkDriverClient diagnostic text; returning true indicates comparability.
bool enumerateProcessesByR0Driver(
    std::vector<KernelProcessSnapshotEntry>* const processListOut,
    std::wstring* const detailTextOut) {
    if (processListOut == nullptr) {
        return false;
    }
    processListOut->clear();
    if (detailTextOut != nullptr) {
        detailTextOut->clear();
    }

    const ksword::ark::DriverClient kDriverClient;
    const ksword::ark::ProcessEnumResult kEnumResult = kDriverClient.enumerateProcesses(
        KSWORD_ARK_ENUM_PROCESS_FLAG_SCAN_CID_TABLE);
    if (!kEnumResult.io.ok) {
        if (detailTextOut != nullptr) {
            *detailTextOut = narrowToWide(kEnumResult.io.message);
        }
        return false;
    }

    processListOut->reserve(kEnumResult.entries.size());
    for (const ksword::ark::ProcessEntry& entry : kEnumResult.entries) {
        KernelProcessSnapshotEntry processEntry{};
        processEntry.processId = entry.processId;
        processEntry.parentProcessId = entry.parentProcessId;
        processEntry.flags = entry.flags;
        processEntry.sessionId = entry.sessionId;
        processEntry.fieldFlags = entry.fieldFlags;
        processEntry.r0Status = entry.r0Status;
        processEntry.protection = entry.protection;
        processEntry.protectionSource = entry.protectionSource;
        processEntry.objectTableAddress = entry.objectTableAddress;
        processEntry.sectionObjectAddress = entry.sectionObjectAddress;
        processEntry.imageName = entry.imageName;
        processEntry.imagePath = entry.imagePath;
        processListOut->push_back(std::move(processEntry));
    }

    if (detailTextOut != nullptr) {
        *detailTextOut = narrowToWide(kEnumResult.io.message);
    }
    return true;
}

// promptOpenPayloadFile shows a common open-file dialog for R0 injection payloads.
// Inputs are owner/filter/title; processing never changes the current directory;
// output is empty when the user cancels.
std::wstring promptOpenPayloadFile(HWND owner, const wchar_t* filter, const wchar_t* title) {
    wchar_t path[32768]{};
    OPENFILENAMEW ofn{};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = owner;
    ofn.lpstrFilter = filter;
    ofn.lpstrFile = path;
    ofn.nMaxFile = static_cast<DWORD>(std::size(path));
    ofn.lpstrTitle = title;
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
    return ::GetOpenFileNameW(&ofn) ? std::wstring(path) : std::wstring();
}

// confirmR0Injection asks for the explicit UI confirmation expected by the
// shared R0 injection protocol. Inputs are owner/action/pid/path; output is true
// only when the user accepts the high-risk operation.
bool confirmR0Injection(HWND owner, const wchar_t* action, DWORD pid, const std::wstring& path) {
    std::wstring message = L"将通过 KswordARK R0 进程注入协议执行操作：";
    message += action ? action : L"注入";
    message += L"\r\n\r\n目标 PID: " + std::to_wstring(pid);
    message += L"\r\nPayload: " + path;
    message += L"\r\n\r\n该操作会在目标进程创建远程线程，可能导致目标崩溃或系统不稳定。是否继续？";
    return ::MessageBoxW(owner, message.c_str(), L"确认 R0 注入", MB_YESNO | MB_DEFBUTTON2 | MB_ICONWARNING) == IDYES;
}

// mergeKernelProcessExtension purpose: Merge R0 enumeration fields into the Light process row without overwriting R3 public API basic information.
// Parameter 'row' is the target UI row, 'kernelProcess' is the R0 row; no return value, the caller decides whether to synthesize a hidden row.
void mergeKernelProcessExtension(
    ProcessSnapshotRow& row,
    const KernelProcessSnapshotEntry& kernelProcess) {
    row.r0EnumFlags = kernelProcess.flags;
    row.r0EnumStatus = kernelProcess.r0Status;
    row.r0EnumImagePath = narrowToWide(kernelProcess.imagePath);
    if ((kernelProcess.fieldFlags & KSWORD_ARK_PROCESS_FIELD_SESSION_PRESENT) != 0U) {
        row.sessionId = kernelProcess.sessionId;
    }
    if (!row.r0EnumImagePath.empty() && row.imagePath.empty()) {
        row.imagePath = row.r0EnumImagePath;
    }
    // The protection byte is provided by the same R0 enumeration; when the field is present, 0 means 'no protection', not a read failure.
    if ((kernelProcess.fieldFlags & KSWORD_ARK_PROCESS_FIELD_PROTECTION_PRESENT) != 0U) {
        wchar_t protectionText[32]{};
        ::swprintf_s(protectionText, L"0x%02X", static_cast<unsigned int>(kernelProcess.protection));
        row.detailTexts[static_cast<std::uint8_t>(ProcessColumnId::kProtection)] = protectionText;
        row.detailTexts[static_cast<std::uint8_t>(ProcessColumnId::kPpl)] =
            kernelProcess.protection == 0 ? L"无" : std::wstring(L"PPL ") + protectionText;
    } else {
        row.detailTexts[static_cast<std::uint8_t>(ProcessColumnId::kProtection)] = L"无（驱动未返回字段）";
        row.detailTexts[static_cast<std::uint8_t>(ProcessColumnId::kPpl)] = L"无（驱动未返回字段）";
    }
    if (kernelProcess.objectTableAddress != 0) {
        wchar_t objectTableText[32]{};
        ::swprintf_s(objectTableText, L"0x%016llX", static_cast<unsigned long long>(kernelProcess.objectTableAddress));
        row.detailTexts[static_cast<std::uint8_t>(ProcessColumnId::kHandleTable)] = objectTableText;
    }
    if (kernelProcess.sectionObjectAddress != 0) {
        wchar_t sectionObjectText[32]{};
        ::swprintf_s(sectionObjectText, L"0x%016llX", static_cast<unsigned long long>(kernelProcess.sectionObjectAddress));
        row.detailTexts[static_cast<std::uint8_t>(ProcessColumnId::kSectionObject)] = sectionObjectText;
    }
}

// buildKernelOnlyRow purpose: Construct a row present in R0 but absent in R3, maintaining consistency with Ksword5.1 hidden process documentation.
// Input kernelProcess is an R0 enumeration; return a ProcessSnapshotRow ready to be appended directly to the ProcessModel.
ProcessSnapshotRow buildKernelOnlyRow(const KernelProcessSnapshotEntry& kernelProcess) {
    ProcessSnapshotRow row{};
    row.processId = static_cast<DWORD>(kernelProcess.processId);
    row.parentProcessId = static_cast<DWORD>(kernelProcess.parentProcessId);
    row.r0KernelOnly = true;
    mergeKernelProcessExtension(row, kernelProcess);

    const std::wstring kImageName = narrowToWide(kernelProcess.imageName);
    const std::wstring kBaseName = kImageName.empty() ? std::wstring(L"Unknown") : kImageName;
    // Weak evidence rows are still reported, but downgraded in wording to 'possible false positive' to remain consistent with Ksword5.1.
    const bool kTerminatingRemnantEvidence =
        (kernelProcess.flags & KSWORD_ARK_PROCESS_FLAG_TERMINATING_OR_EXITED) != 0U;
    const bool kCidReferenceFailedEvidence =
        (kernelProcess.flags & KSWORD_ARK_PROCESS_FLAG_CID_TABLE_REFERENCE_FAILED) != 0U;
    const bool kCidTableWeakEvidence = kTerminatingRemnantEvidence || kCidReferenceFailedEvidence;
    row.imageName = kCidTableWeakEvidence
        ? (L"[R0?] " + kBaseName + L"（可能为误报）")
        : (L"[R0] " + kBaseName);
    row.imagePath = kTerminatingRemnantEvidence
        ? L"[可能为误报：进程已退出，EPROCESS 仍被句柄引用]"
        : (kCidReferenceFailedEvidence
            ? L"[可能为误报：CID Table命中但对象引用失败]"
            : L"[仅内核枚举可见]");
    row.r0AuditSummary = kCidTableWeakEvidence ? L"KernelOnly(可能为误报)" : L"KernelOnly(Hidden?)";
    row.r0AuditDetail = kTerminatingRemnantEvidence
        ? L"可能为误报：EPROCESS 已退出（ExitStatus 非 STATUS_PENDING），仍留在 PspCidTable"
        : (kCidReferenceFailedEvidence
            ? L"可能为误报：CID Table命中但对象引用失败"
            : L"仅内核枚举可见");
    row.r0AuditDetail += L"; flags=" + flagHexText(kernelProcess.flags);
    row.r0AuditDetail += L"; status=" + processR0StatusText(kernelProcess.r0Status);
    return row;
}

// applyDefaultHiddenProcessAudit purpose: Perform default R0/R3 process list comparison to identify suspected hidden processes.
// Returns a status bar summary; if the driver is unavailable, only a failure summary is returned, without affecting the R3 enumeration results in rows.
HiddenProcessAuditResult applyDefaultHiddenProcessAudit(std::vector<ProcessSnapshotRow>& rows) {
    HiddenProcessAuditResult result{};
    std::vector<KernelProcessSnapshotEntry> kernelRows;
    std::wstring queryDetail;
    if (!enumerateProcessesByR0Driver(&kernelRows, &queryDetail)) {
        result.detailText = L"R0隐藏检查: 待驱动装载/查询失败";
        if (!queryDetail.empty()) {
            result.detailText += L" " + queryDetail;
        }
        return result;
    }

    result.querySucceeded = true;
    result.kernelEnumeratedCount = kernelRows.size();

    std::unordered_map<DWORD, const KernelProcessSnapshotEntry*> kernelByPid;
    kernelByPid.reserve(kernelRows.size() * 2U + 1U);
    for (const KernelProcessSnapshotEntry& kernelProcess : kernelRows) {
        kernelByPid[static_cast<DWORD>(kernelProcess.processId)] = &kernelProcess;
    }

    std::unordered_set<DWORD> userPidSet;
    userPidSet.reserve(rows.size() * 2U + 1U);
    for (ProcessSnapshotRow& row : rows) {
        userPidSet.insert(row.processId);
        const auto kFound = kernelByPid.find(row.processId);
        if (kFound != kernelByPid.end()) {
            mergeKernelProcessExtension(row, *kFound->second);
        }
    }

    for (const KernelProcessSnapshotEntry& kernelProcess : kernelRows) {
        const DWORD kProcessId = static_cast<DWORD>(kernelProcess.processId);
        if (userPidSet.find(kProcessId) != userPidSet.end()) {
            continue;
        }
        rows.push_back(buildKernelOnlyRow(kernelProcess));
        userPidSet.insert(kProcessId);
        ++result.kernelOnlyCount;
    }

    result.detailText = L"R0隐藏检查: 内核返回 " +
        std::to_wstring(result.kernelEnumeratedCount) +
        L"，疑似隐藏 " +
        std::to_wstring(result.kernelOnlyCount);
    return result;
}

// sourceMaskText renders the process cross-view source matrix. Input is the raw
// sourceMask from R0; processing keeps names aligned with the shared protocol.
std::wstring sourceMaskText(ULONG sourceMask) {
    std::vector<std::wstring> parts;
    if ((sourceMask & KSWORD_ARK_CROSSVIEW_SOURCE_PUBLIC_WALK) != 0) {
        parts.push_back(L"Public");
    }
    if ((sourceMask & KSWORD_ARK_CROSSVIEW_SOURCE_ACTIVE_LIST) != 0) {
        parts.push_back(L"ActiveProcessLinks");
    }
    if ((sourceMask & KSWORD_ARK_CROSSVIEW_SOURCE_CID_TABLE) != 0) {
        parts.push_back(L"CID");
    }
    if (parts.empty()) {
        return L"无来源";
    }

    std::wstring text;
    for (const std::wstring& part : parts) {
        if (!text.empty()) {
            text += L"+";
        }
        text += part;
    }
    return text;
}

// anomalyMaskText renders known process/thread anomaly bits as evidence labels.
// Input is the raw anomalyFlags mask; output keeps unknown future bits visible.
std::wstring anomalyMaskText(ULONG anomalyFlags) {
    if (anomalyFlags == 0) {
        return L"未见异常";
    }

    std::vector<std::wstring> parts;
    if ((anomalyFlags & KSWORD_ARK_CROSSVIEW_ANOMALY_CID_ONLY) != 0) {
        parts.push_back(L"CID-only");
    }
    if ((anomalyFlags & KSWORD_ARK_CROSSVIEW_ANOMALY_ACTIVE_ONLY) != 0) {
        parts.push_back(L"Active-only");
    }
    if ((anomalyFlags & KSWORD_ARK_CROSSVIEW_ANOMALY_MISSING_FROM_ACTIVE_LIST) != 0) {
        parts.push_back(L"缺ActiveProcessLinks");
    }
    if ((anomalyFlags & KSWORD_ARK_CROSSVIEW_ANOMALY_MISSING_FROM_CID_TABLE) != 0) {
        parts.push_back(L"缺CID");
    }
    if ((anomalyFlags & KSWORD_ARK_CROSSVIEW_ANOMALY_PID_FIELD_MISMATCH) != 0) {
        parts.push_back(L"PID不一致");
    }

    std::wstring text;
    for (const std::wstring& part : parts) {
        if (!text.empty()) {
            text += L"; ";
        }
        text += part;
    }
    if (text.empty()) {
        text = L"未知异常位 " + flagHexText(anomalyFlags);
    }
    return text;
}

// applyR0ProcessAuditRows annotates R3 process rows with process cross-view
// evidence. Inputs are mutable rows and a status suffix; processing calls only
// ArkDriverClient wrappers and never issues raw DeviceIoControl from the UI.
void applyR0ProcessAuditRows(std::vector<ProcessSnapshotRow>& rows, std::wstring& statusSuffix) {
    const ksword::ark::DriverClient kDriverClient;
    const ksword::ark::ProcessCrossViewResult kAudit = kDriverClient.queryProcessCrossView(
        KSWORD_ARK_PROCESS_CROSSVIEW_FLAG_INCLUDE_ALL,
        0,
        0,
        KSWORD_ARK_CROSSVIEW_DEFAULT_MAX_NODES);
    if (!kAudit.io.ok) {
        statusSuffix = L"；R0审计不可用: " + narrowToWide(kAudit.io.message);
        for (ProcessSnapshotRow& row : rows) {
            if (row.r0KernelOnly) {
                row.r0AuditSummary = row.r0AuditSummary.empty() ? L"KernelOnly(Hidden?)" : row.r0AuditSummary;
                if (!row.r0AuditDetail.empty()) {
                    row.r0AuditDetail += L"; CrossView不可用";
                } else {
                    row.r0AuditDetail = kAudit.unsupported ? L"驱动不支持CrossView" : L"CrossView查询失败";
                }
                continue;
            }
            row.r0AuditSummary = L"不可用";
            row.r0AuditDetail = kAudit.unsupported ? L"驱动不支持" : L"查询失败";
        }
        return;
    }

    std::unordered_map<DWORD, const ksword::ark::ProcessCrossViewEntry*> auditByPid;
    auditByPid.reserve(kAudit.entries.size());
    for (const ksword::ark::ProcessCrossViewEntry& entry : kAudit.entries) {
        auditByPid[static_cast<DWORD>(entry.processId)] = &entry;
    }

    std::size_t matched = 0;
    std::size_t anomalous = 0;
    for (ProcessSnapshotRow& row : rows) {
        const auto kFound = auditByPid.find(row.processId);
        if (kFound == auditByPid.end()) {
            if (row.r0KernelOnly) {
                row.r0AuditSummary = row.r0AuditSummary.empty() ? L"KernelOnly(Hidden?)" : row.r0AuditSummary;
                if (!row.r0AuditDetail.empty()) {
                    row.r0AuditDetail += L"; CrossView未返回";
                } else {
                    row.r0AuditDetail = L"仅 R0 枚举返回，CrossView未返回";
                }
                continue;
            }
            row.r0AuditSummary = L"R3-only";
            row.r0AuditDetail = L"R0未返回";
            continue;
        }

        const ksword::ark::ProcessCrossViewEntry& entry = *kFound->second;
        row.r0ProcessObjectAddress = static_cast<std::uintptr_t>(entry.objectAddress);
        row.r0SourceMask = entry.sourceMask;
        row.r0AnomalyFlags = entry.anomalyFlags;
        row.r0Confidence = entry.confidence;
        row.r0AuditSummary = sourceMaskText(row.r0SourceMask);
        row.r0AuditDetail = anomalyMaskText(row.r0AnomalyFlags);
        row.r0AuditDetail += L"; conf=" + std::to_wstring(row.r0Confidence);
        if (!entry.detail.empty()) {
            row.r0AuditDetail += L"; " + narrowToWide(entry.detail);
        }
        ++matched;
        if (row.r0AnomalyFlags != 0) {
            ++anomalous;
        }
    }

    statusSuffix = L"；R0审计匹配 " + std::to_wstring(matched) +
        L"/" + std::to_wstring(rows.size()) +
        L"，异常 " + std::to_wstring(anomalous) +
        L"，返回 " + std::to_wstring(kAudit.returnedCount) +
        L"/" + std::to_wstring(kAudit.totalCount);
}

// writeClipboardText copies Unicode text to the Windows clipboard. Inputs are
// the owner HWND and text. Processing allocates CF_UNICODETEXT global memory and
// transfers ownership to the clipboard. Return value reports success.
bool writeClipboardText(HWND owner, const std::wstring& text) {
    return ksword::ui::copyTextToClipboard(owner, text, L"进程模块");
}

// detailDemandForColumns purpose: request additional collection from the main process library only for the currently visible depth columns.
std::uint32_t detailDemandForColumns(const std::vector<ProcessColumnId>& columns) {
    std::uint32_t demand = ks::process::process_detail_demand::kNone;
    const auto kHas = [&columns](ProcessColumnId id) { return std::find(columns.begin(), columns.end(), id) != columns.end(); };
    if (kHas(ProcessColumnId::kGpuEngine)) demand |= ks::process::process_detail_demand::kGpuEngine;
    if (kHas(ProcessColumnId::kGpuDedicatedMemory) || kHas(ProcessColumnId::kGpuSharedMemory)) demand |= ks::process::process_detail_demand::kGpuMemory;
    if (kHas(ProcessColumnId::kPackageName)) demand |= ks::process::process_detail_demand::kPackageName;
    if (kHas(ProcessColumnId::kDescription)) demand |= ks::process::process_detail_demand::kFileDescription;
    if (kHas(ProcessColumnId::kDpiAwareness)) demand |= ks::process::process_detail_demand::kDpiAwareness;
    if (kHas(ProcessColumnId::kUacVirtualization)) demand |= ks::process::process_detail_demand::kUacVirtualization;
    if (kHas(ProcessColumnId::kDataExecutionPrevention) || kHas(ProcessColumnId::kControlFlowGuard) || kHas(ProcessColumnId::kHardwareStackProtection)) demand |= ks::process::process_detail_demand::kMitigationPolicy;
    if (kHas(ProcessColumnId::kJobObject)) demand |= ks::process::process_detail_demand::kJobObject;
    return demand;
}

// applyR0KernelColumnDetails purpose: Called only when kernel columns are visible to query R0 HandleTable and SectionObject, then populate the list.
void applyR0KernelColumnDetails(std::vector<ProcessSnapshotRow>& rows, const std::vector<ProcessColumnId>& columns) {
    const bool kNeedHandleTable = std::find(columns.begin(), columns.end(), ProcessColumnId::kHandleTable) != columns.end();
    const bool kNeedSectionObject = std::find(columns.begin(), columns.end(), ProcessColumnId::kSectionObject) != columns.end();
    if (!kNeedHandleTable && !kNeedSectionObject) return;

    const ksword::ark::DriverClient kDriverClient;
    for (ProcessSnapshotRow& row : rows) {
        if (row.processId == 0 || row.r0KernelOnly) continue;
        if (kNeedHandleTable) {
            const ksword::ark::HandleEnumResult kHandles = kDriverClient.enumerateProcessHandles(row.processId);
            if (kHandles.io.ok) {
                row.detailTexts[static_cast<std::uint8_t>(ProcessColumnId::kHandleTable)] =
                    L"可用：" + std::to_wstring(kHandles.returnedCount) + L"/" + std::to_wstring(kHandles.totalCount) + L" 个句柄";
            } else {
                row.detailTexts[static_cast<std::uint8_t>(ProcessColumnId::kHandleTable)] = L"R0 查询失败";
            }
        }
        if (kNeedSectionObject) {
            const ksword::ark::ProcessSectionQueryResult kSection = kDriverClient.queryProcessSection(row.processId);
            if (kSection.io.ok) {
                wchar_t addressText[32]{};
                ::swprintf_s(addressText, L"0x%016llX", static_cast<unsigned long long>(kSection.sectionObjectAddress));
                row.detailTexts[static_cast<std::uint8_t>(ProcessColumnId::kSectionObject)] =
                    kSection.sectionObjectAddress != 0 ? addressText : L"无 SectionObject";
            } else {
                row.detailTexts[static_cast<std::uint8_t>(ProcessColumnId::kSectionObject)] = L"R0 查询失败";
            }
        }
    }
}

// applyMainProcessDetails purpose: Reuse the process library linked in Ksword5.1 to write real R3 depth fields into Light rows.
void applyMainProcessDetails(std::vector<ProcessSnapshotRow>& rows, const std::vector<ProcessColumnId>& columns) {
    const std::uint32_t kDemand = detailDemandForColumns(columns);
    const std::vector<ks::process::ProcessRecord> kRecords = ks::process::enumerateProcesses(ks::process::ProcessEnumStrategy::kAuto, nullptr, kDemand);
    std::unordered_map<std::uint32_t, const ks::process::ProcessRecord*> byPid;
    for (const ks::process::ProcessRecord& record : kRecords) byPid[record.pid] = &record;
    const auto kPut = [](ProcessSnapshotRow& row, ProcessColumnId id, const std::wstring& text) { if (!text.empty()) row.detailTexts[static_cast<std::uint8_t>(id)] = text; };
    const bool kWantsSignature = std::find(columns.begin(), columns.end(), ProcessColumnId::kSignature) != columns.end();
    static std::atomic_size_t signatureCursor{ 0 };
    const std::size_t kSignatureStart = rows.empty() ? 0 : signatureCursor.fetch_add(24U) % rows.size();
    std::size_t signatureOrdinal = 0;
    for (ProcessSnapshotRow& row : rows) {
        const auto kFound = byPid.find(row.processId);
        if (kFound == byPid.end()) continue;
        const ks::process::ProcessRecord& record = *kFound->second;
        bool verifySignature = false;
        // Static details are collected only for views requiring static fields; signature verification also occurs in the background.
        ks::process::ProcessRecord details{};
        const bool kStaticNeeded = std::any_of(columns.begin(), columns.end(), [](ProcessColumnId id) {
            return id == ProcessColumnId::kPath || id == ProcessColumnId::kCommandLine || id == ProcessColumnId::kUser || id == ProcessColumnId::kSignature || id == ProcessColumnId::kIsAdmin || id == ProcessColumnId::kPplLevel || id == ProcessColumnId::kPowerThrottling || id == ProcessColumnId::kPackageName || id == ProcessColumnId::kDescription || id == ProcessColumnId::kJobObject || id == ProcessColumnId::kUacVirtualization || id == ProcessColumnId::kDataExecutionPrevention || id == ProcessColumnId::kControlFlowGuard || id == ProcessColumnId::kHardwareStackProtection || id == ProcessColumnId::kDpiAwareness;
        });
        if (kStaticNeeded) {
            // WinVerifyTrust may block for a long time on protected or network-path images; verify a limited number per round, and explicitly mark other rows as pending verification.
            const std::size_t kSignatureOffset = rows.empty() ? 0 : (signatureOrdinal++ + rows.size() - kSignatureStart) % rows.size();
            verifySignature = kWantsSignature && kSignatureOffset < 24U;
            ks::process::queryProcessStaticDetailByPid(record.pid, details, verifySignature);
            // This step actually executes on-demand retrieval of mitigation policies, UAC, jobs, package names, and DPI; do not pass only 'demand' to the enumerator.
            ks::process::fillProcessOnDemandDetails(details, kDemand, nullptr);
        }
        const ks::process::ProcessRecord& source = details.staticDetailsReady ? details : record;
        kPut(row, ProcessColumnId::kPath, narrowToWide(source.imagePath));
        kPut(row, ProcessColumnId::kCommandLine, narrowToWide(source.commandLine));
        kPut(row, ProcessColumnId::kUser, narrowToWide(source.userName));
        kPut(row, ProcessColumnId::kStartTime, narrowToWide(record.startTimeText));
        kPut(row, ProcessColumnId::kSignature, kWantsSignature && !verifySignature ? L"待验证" : narrowToWide(source.signatureState));
        kPut(row, ProcessColumnId::kDescription, narrowToWide(source.fileDescription));
        kPut(row, ProcessColumnId::kPackageName, narrowToWide(source.packageFullName));
        kPut(row, ProcessColumnId::kIsAdmin, source.isAdmin ? L"是" : L"否");
        kPut(row, ProcessColumnId::kPowerThrottling, source.efficiencyModeSupported ? (source.efficiencyModeEnabled ? L"已启用" : L"已禁用") : L"不支持");
        kPut(row, ProcessColumnId::kStatus, record.processStateKnown ? (record.processSuspended ? L"已挂起" : L"运行中") : L"未知");
        kPut(row, ProcessColumnId::kGpuEngine, narrowToWide(record.gpuEngineText));
        kPut(row, ProcessColumnId::kJobObject, source.jobObjectKnown ? (source.inJobObject ? L"是" : L"否") : L"访问受限");
        kPut(row, ProcessColumnId::kUacVirtualization, std::to_wstring(static_cast<unsigned int>(source.uacVirtualizationState)));
        kPut(row, ProcessColumnId::kDataExecutionPrevention, std::to_wstring(static_cast<unsigned int>(source.dataExecutionPreventionState)));
        kPut(row, ProcessColumnId::kControlFlowGuard, std::to_wstring(static_cast<unsigned int>(source.controlFlowGuardState)));
        kPut(row, ProcessColumnId::kHardwareStackProtection, std::to_wstring(static_cast<unsigned int>(source.hardwareStackProtectionState)));
        kPut(row, ProcessColumnId::kDpiAwareness, std::to_wstring(static_cast<unsigned int>(source.dpiAwarenessLevel)));
        std::uint32_t protectionLevel = 0;
        std::string protectionText;
        if (ks::process::queryProcessProtectionLevelByPid(record.pid, &protectionLevel, &protectionText, nullptr)) kPut(row, ProcessColumnId::kPplLevel, narrowToWide(protectionText));
        else kPut(row, ProcessColumnId::kPplLevel, L"访问受限");
        if (record.gpuMemoryKnown) { kPut(row, ProcessColumnId::kGpuDedicatedMemory, formatByteSize(record.gpuDedicatedMemoryBytes)); kPut(row, ProcessColumnId::kGpuSharedMemory, formatByteSize(record.gpuSharedMemoryBytes)); }
    }
}

// collectProcessRefreshSnapshot performs every potentially blocking query for a
// process refresh. It never accesses HWNDs or ProcessViewState and is safe for
// AsyncSnapshotTask's worker thread.
ProcessRefreshSnapshot collectProcessRefreshSnapshot(const std::vector<ProcessColumnId>& columns) {
    ProcessRefreshSnapshot snapshot{};
    snapshot.enumeration = enumerateProcessesByNtQuerySystemInformation();
    if (!snapshot.enumeration.success) {
        return snapshot;
    }
    applyMainProcessDetails(snapshot.enumeration.rows, columns);
    snapshot.hiddenAudit = applyDefaultHiddenProcessAudit(snapshot.enumeration.rows);
    applyR0ProcessAuditRows(snapshot.enumeration.rows, snapshot.crossViewStatusSuffix);
    applyR0KernelColumnDetails(snapshot.enumeration.rows, columns);
    return snapshot;
}

// applyProcessRefresh installs a completed immutable snapshot on the UI thread.
// It records lifecycle differences and commits the owner-data presentation with
// selective ListView invalidation, preserving a stable process-list surface.
void applyProcessRefresh(ProcessViewState& state, ProcessRefreshSnapshot snapshot) {
    if (!snapshot.enumeration.success) {
        state.model.setRows({});
        rebuildRows(state);
        setStatus(state, L"进程枚举失败: " + snapshot.enumeration.diagnosticText);
        return;
    }

    std::vector<ProcessSnapshotRow> rows = std::move(snapshot.enumeration.rows);
    const HiddenProcessAuditResult& hiddenAudit = snapshot.hiddenAudit;
    const ULONGLONG kNowMs = ::GetTickCount64();
    const ULONGLONG kElapsedMs = state.previousSampleTickMs == 0 ? 0 : kNowMs - state.previousSampleTickMs;
    const DWORD kProcessorCount = std::max<DWORD>(1, ::GetActiveProcessorCount(ALL_PROCESSOR_GROUPS));
    std::unordered_map<std::wstring, ULONGLONG> newCpuTimes;
    std::unordered_map<std::wstring, ProcessSnapshotRow> activeRowsByIdentity;
    newCpuTimes.reserve(rows.size());
    activeRowsByIdentity.reserve(rows.size());
    const std::unordered_map<std::wstring, ProcessRowVisualState> kPreviousVisualStates =
        std::move(state.visualStateByIdentity);
    state.visualStateByIdentity.clear();
    for (ProcessSnapshotRow& row : rows) {
        const std::wstring kIdentityKey = processStableKey(row.processId, row.creationTime100ns);
        const ULONGLONG kTotal100ns = row.kernelTime100ns + row.userTime100ns;
        // Adjacent snapshot deltas are calculated only between instances with the same PID and creation time to avoid incorrect increments caused by PID recycling.
        const auto kPreviousRow = state.lastActiveRowsByIdentity.find(kIdentityKey);
        if (kPreviousRow != state.lastActiveRowsByIdentity.end()) {
            row.workingSetDeltaBytes = static_cast<LONGLONG>(row.workingSetBytes) - static_cast<LONGLONG>(kPreviousRow->second.workingSetBytes);
            row.pageFaultDelta = static_cast<LONGLONG>(row.pageFaultCount) - static_cast<LONGLONG>(kPreviousRow->second.pageFaultCount);
        }
        newCpuTimes[kIdentityKey] = kTotal100ns;
        activeRowsByIdentity[kIdentityKey] = row;
        if (state.hasLastActiveSnapshot &&
            state.lastActiveRowsByIdentity.find(kIdentityKey) == state.lastActiveRowsByIdentity.end()) {
            state.visualStateByIdentity[kIdentityKey] = ProcessRowVisualState::kAdded;
        }
        row.cpuUsagePercent = 0.0;
        const auto kPrevious = state.previousCpuTime100ns.find(kIdentityKey);
        if (kElapsedMs > 0 && kPrevious != state.previousCpuTime100ns.end() && kTotal100ns >= kPrevious->second) {
            const ULONGLONG kDelta100ns = kTotal100ns - kPrevious->second;
            const double kCapacity100ns = static_cast<double>(kElapsedMs) * 10000.0 * static_cast<double>(kProcessorCount);
            if (kCapacity100ns > 0.0) {
                row.cpuUsagePercent = std::clamp((static_cast<double>(kDelta100ns) * 100.0) / kCapacity100ns, 0.0, 999.9);
            }
        }
    }
    if (state.hasLastActiveSnapshot) {
        for (const auto& oldRow : state.lastActiveRowsByIdentity) {
            if (activeRowsByIdentity.find(oldRow.first) == activeRowsByIdentity.end()) {
                ProcessSnapshotRow removed = oldRow.second;
                removed.cpuUsagePercent = 0.0;
                rows.push_back(removed);
                state.visualStateByIdentity[oldRow.first] = ProcessRowVisualState::kRemoved;
            }
        }
    }

    const std::size_t kActiveCount = activeRowsByIdentity.size();
    const std::size_t kAddedCount = std::count_if(
        state.visualStateByIdentity.begin(),
        state.visualStateByIdentity.end(),
        [](const auto& entry) { return entry.second == ProcessRowVisualState::kAdded; });
    const std::size_t kRemovedCount = std::count_if(
        state.visualStateByIdentity.begin(),
        state.visualStateByIdentity.end(),
        [](const auto& entry) { return entry.second == ProcessRowVisualState::kRemoved; });

    state.previousCpuTime100ns = std::move(newCpuTimes);
    state.previousSampleTickMs = kNowMs;
    state.lastActiveRowsByIdentity = std::move(activeRowsByIdentity);
    state.hasLastActiveSnapshot = true;

    state.model.setRows(std::move(rows));
    rebuildRows(state, &kPreviousVisualStates);
    setStatus(state,
        L"已同步 " + std::to_wstring(kActiveCount) +
        L" 个进程；新增 " + std::to_wstring(kAddedCount) +
        L"，退出 " + std::to_wstring(kRemovedCount) +
        L" 个进程；刷新 " + std::to_wstring(state.refreshIntervalSeconds) +
        L"s；" + hiddenAudit.detailText + snapshot.crossViewStatusSuffix +
        L"；左 Ctrl 按下时跳过自动刷新。");
}

// beginProcessRefresh only schedules work and updates lightweight feedback. A
// running request is coalesced by AsyncSnapshotTask so fast timers and manual
// refreshes cannot start concurrent R0/R3 enumeration passes.
void beginProcessRefresh(ProcessViewState& state) {
    if (!state.refreshTask) {
        return;
    }
    setStatus(state, state.refreshTask->running() ? L"进程刷新已排队，等待当前快照完成…" : L"正在后台枚举进程与 R0 证据…");
    if (state.refreshButton) {
        ::EnableWindow(state.refreshButton, FALSE);
    }
    const std::vector<ProcessColumnId> kRequestedColumns = state.activeColumns;
    state.refreshTask->request(
        [kRequestedColumns]() { return collectProcessRefreshSnapshot(kRequestedColumns); },
        [&state](std::uint64_t, std::optional<ProcessRefreshSnapshot>&& snapshot, std::exception_ptr error) {
            if (state.refreshButton) {
                ::EnableWindow(state.refreshButton, TRUE);
            }
            if (error || !snapshot.has_value()) {
                setStatus(state, L"进程刷新任务异常结束。请检查驱动状态和访问权限。");
                return;
            }
            applyProcessRefresh(state, std::move(*snapshot));
        });
}

// applyPreset: Apply a built-in compact column group, then immediately rebuild the headers and immutable display snapshot.
void applyPreset(ProcessViewState& state, ProcessViewPreset preset) {
    state.preset = preset;
    state.activeColumns = defaultProcessColumns(preset);
    rebuildColumns(state);
    rebuildRows(state);
    updateToolbarTexts(state);
    ::PostMessageW(state.hwnd, kMsgRequestRefresh, 0, 0);
    setStatus(state, std::wstring(L"已切换到") + processViewPresetTitle(preset) + L"列组。");
}

// toggleColumn purpose: shows or hides a logical column based on user menu selection; the Name and PID columns are always retained.
void toggleColumn(ProcessViewState& state, ProcessColumnId column) {
    const ProcessColumnDescriptor* descriptor = findProcessColumn(column);
    if (!descriptor || descriptor->locked) return;
    const auto kFound = std::find(state.activeColumns.begin(), state.activeColumns.end(), column);
    if (kFound == state.activeColumns.end()) state.activeColumns.push_back(column);
    else state.activeColumns.erase(kFound);
    state.preset = ProcessViewPreset::kCustom;
    rebuildColumns(state);
    rebuildRows(state);
    updateToolbarTexts(state);
    ::PostMessageW(state.hwnd, kMsgRequestRefresh, 0, 0);
}

// ColumnChooserState: Stores controls for a temporary modal column selection window and the owning process page.
struct ColumnChooserState {
    ProcessViewState* owner = nullptr;
    std::vector<HWND> checkBoxes;
};

// columnChooserProc purpose: handle confirmation, cancellation, and destruction messages in the column selection modal window.
LRESULT CALLBACK columnChooserProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam) {
    auto* chooser = reinterpret_cast<ColumnChooserState*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    if (message == WM_NCCREATE) {
        const auto* create = reinterpret_cast<const CREATESTRUCTW*>(lParam);
        chooser = create ? static_cast<ColumnChooserState*>(create->lpCreateParams) : nullptr;
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(chooser));
    }
    if (!chooser) return ::DefWindowProcW(hwnd, message, wParam, lParam);

    if (message == WM_CREATE) {
        const int kColumnWidth = 180;
        const int kRowHeight = 25;
        for (std::size_t index = 0; index < processColumnDescriptors().size(); ++index) {
            const ProcessColumnDescriptor& descriptor = processColumnDescriptors()[index];
            const int kVisualColumn = static_cast<int>(index / 20U);
            const int kVisualRow = static_cast<int>(index % 20U);
            HWND check = ::CreateWindowExW(0, WC_BUTTONW, descriptor.title,
                WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX,
                14 + kVisualColumn * kColumnWidth, 42 + kVisualRow * kRowHeight,
                kColumnWidth - 8, kRowHeight, hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(100 + index)),
                ::GetModuleHandleW(nullptr), nullptr);
            if (check) {
                const bool kVisible = std::find(chooser->owner->activeColumns.begin(), chooser->owner->activeColumns.end(), descriptor.id) != chooser->owner->activeColumns.end();
                ::SendMessageW(check, BM_SETCHECK, kVisible ? BST_CHECKED : BST_UNCHECKED, 0);
                ::EnableWindow(check, !descriptor.locked);
                chooser->checkBoxes.push_back(check);
            }
        }
        ksword::ui::createButton(hwnd, kColumnChooserApplyId, L"应用", 380, 555, 86, 28);
        ksword::ui::createButton(hwnd, kColumnChooserCancelId, L"取消", 474, 555, 86, 28);
        ksword::ui::createText(hwnd, 0, L"选择需要显示的列；名称与 PID 是固定标识列。", 14, 12, 540, 22);
        return 0;
    }
    if (message == WM_COMMAND) {
        const int kId = LOWORD(wParam);
        if (kId == kColumnChooserApplyId) {
            std::vector<ProcessColumnId> selected;
            for (std::size_t index = 0; index < chooser->checkBoxes.size() && index < processColumnDescriptors().size(); ++index) {
                if (::SendMessageW(chooser->checkBoxes[index], BM_GETCHECK, 0, 0) == BST_CHECKED) selected.push_back(processColumnDescriptors()[index].id);
            }
            chooser->owner->activeColumns = std::move(selected);
            chooser->owner->preset = ProcessViewPreset::kCustom;
            rebuildColumns(*chooser->owner);
            rebuildRows(*chooser->owner);
            updateToolbarTexts(*chooser->owner);
            ::PostMessageW(chooser->owner->hwnd, kMsgRequestRefresh, 0, 0);
            ::DestroyWindow(hwnd);
            return 0;
        }
        if (kId == kColumnChooserCancelId) { ::DestroyWindow(hwnd); return 0; }
    }
    if (message == WM_CLOSE) { ::DestroyWindow(hwnd); return 0; }
    if (message == WM_NCDESTROY) { ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0); return 0; }
    return ::DefWindowProcW(hwnd, message, wParam, lParam);
}

// showColumnChooser purpose: Create a modal checkbox window; column layout is written back only to the current ProcessViewState.
void showColumnChooser(ProcessViewState& state) {
    static bool registered = false;
    if (!registered) {
        WNDCLASSW windowClass{};
        windowClass.lpfnWndProc = columnChooserProc;
        windowClass.hInstance = ::GetModuleHandleW(nullptr);
        windowClass.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
        windowClass.hbrBackground = ksword::ui::appTheme().windowBrush();
        windowClass.lpszClassName = kColumnChooserClass;
        registered = ::RegisterClassW(&windowClass) != FALSE || ::GetLastError() == ERROR_CLASS_ALREADY_EXISTS;
    }
    if (!registered) return;
    ColumnChooserState chooser{ &state, {} };
    HWND dialog = ::CreateWindowExW(WS_EX_DLGMODALFRAME, kColumnChooserClass, L"选择列",
        WS_CAPTION | WS_SYSMENU | WS_POPUP | WS_VISIBLE,
        CW_USEDEFAULT, CW_USEDEFAULT, 575, 625, state.hwnd, nullptr, ::GetModuleHandleW(nullptr), &chooser);
    if (!dialog) return;
    ::EnableWindow(state.hwnd, FALSE);
    MSG message{};
    while (::IsWindow(dialog) && ::GetMessageW(&message, nullptr, 0, 0) > 0) {
        if (!::IsDialogMessageW(dialog, &message)) { ::TranslateMessage(&message); ::DispatchMessageW(&message); }
    }
    ::EnableWindow(state.hwnd, TRUE);
    ::SetForegroundWindow(state.hwnd);
}

// showColumnMenu purpose: Display a runtime column selection menu organized by groups; the same entry is reused by both the toolbar and the header right-click context.
void showColumnMenu(ProcessViewState& state, POINT screenPoint) {
    HMENU menu = ::CreatePopupMenu();
    if (!menu) return;
    std::size_t menuIndex = 0;
    for (ProcessColumnGroup group : { ProcessColumnGroup::kGeneral, ProcessColumnGroup::kPerformance, ProcessColumnGroup::kMemory, ProcessColumnGroup::kIo, ProcessColumnGroup::kSecurity, ProcessColumnGroup::kKernel }) {
        HMENU groupMenu = ::CreatePopupMenu();
        for (const ProcessColumnDescriptor& descriptor : processColumnDescriptors()) {
            if (descriptor.group != group) continue;
            const bool kVisible = std::find(state.activeColumns.begin(), state.activeColumns.end(), descriptor.id) != state.activeColumns.end();
            const UINT kFlags = MF_STRING | (kVisible ? MF_CHECKED : MF_UNCHECKED) | (descriptor.locked ? MF_GRAYED : 0U);
            ::AppendMenuW(groupMenu, kFlags, kColumnMenuBaseId + static_cast<UINT>(menuIndex), descriptor.title);
            ++menuIndex;
        }
        ::AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(groupMenu), processColumnGroupTitle(group));
    }
    ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    ::AppendMenuW(menu, MF_STRING, kColumnMenuBaseId + 1000, L"恢复当前预设默认列");
    const UINT kCommand = ::TrackPopupMenu(menu, TPM_RETURNCMD | TPM_RIGHTBUTTON, screenPoint.x, screenPoint.y, 0, state.hwnd, nullptr);
    ::DestroyMenu(menu);
    if (kCommand == kColumnMenuBaseId + 1000) { applyPreset(state, state.preset == ProcessViewPreset::kCustom ? ProcessViewPreset::kMonitor : state.preset); return; }
    if (kCommand >= kColumnMenuBaseId && kCommand < kColumnMenuBaseId + processColumnDescriptors().size()) toggleColumn(state, processColumnDescriptors()[kCommand - kColumnMenuBaseId].id);
}

// toggleRefreshPaused flips automatic refresh. Input is the page state;
// processing updates the toolbar and status; no value is returned.
void toggleRefreshPaused(ProcessViewState& state) {
    state.refreshPaused = !state.refreshPaused;
    updateToolbarTexts(state);
    setStatus(state, state.refreshPaused ? L"自动刷新已暂停。" : L"自动刷新已恢复。");
}

// selectPid highlights all visible rows matching one PID. Inputs are page state
// and PID. Processing clears existing selection then selects/focuses the first
// matching row. Return value reports whether a visible row was found.
bool selectPid(ProcessViewState& state, DWORD pid) {
    if (!state.listView) {
        return false;
    }

    ListView_SetItemState(state.listView, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
    bool found = false;
    for (int item = 0; item < ListView_GetItemCount(state.listView); ++item) {
        const int kDisplayIndex = displayIndexFromListItem(state, item);
        if (kDisplayIndex < 0 || static_cast<std::size_t>(kDisplayIndex) >= state.presentationRows.size()) {
            continue;
        }
        if (state.presentationRows[static_cast<std::size_t>(kDisplayIndex)].processId == pid) {
            ListView_SetItemState(state.listView, item, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
            ListView_EnsureVisible(state.listView, item, FALSE);
            found = true;
        }
    }
    return found;
}

// beginPicker starts the drag-select interaction. Input is page state; processing
// captures the mouse to the page and changes the cursor prompt. The selected PID
// is resolved later from WindowFromPoint on mouse release; no value is returned.
void beginPicker(ProcessViewState& state) {
    state.pickingWindow = true;
    ::SetCapture(state.hwnd);
    ::SetCursor(::LoadCursorW(nullptr, IDC_CROSS));
    setStatus(state, L"拖动到目标窗口后释放鼠标，将根据窗口 HWND 选中对应进程。");
}

// completePicker ends drag-select. Input is page state. Processing reads the
// current cursor position, resolves the window PID with GetWindowThreadProcessId,
// selects a matching row, and updates status. No value is returned.
void completePicker(ProcessViewState& state) {
    state.pickingWindow = false;
    if (::GetCapture() == state.hwnd) {
        ::ReleaseCapture();
    }

    POINT point{};
    ::GetCursorPos(&point);
    HWND target = ::WindowFromPoint(point);
    DWORD pid = 0;
    if (target) {
        ::GetWindowThreadProcessId(target, &pid);
    }

    if (pid != 0 && selectPid(state, pid)) {
        setStatus(state, L"已通过窗口拖选定位 PID " + std::to_wstring(pid) + L"。");
    } else if (pid != 0) {
        setStatus(state, L"窗口属于 PID " + std::to_wstring(pid) + L"，但当前列表中未找到可见行。请刷新后重试。");
    } else {
        setStatus(state, L"未能从释放位置解析窗口进程。");
    }
}

// isReadOnlyProcessAction identifies operations that do not alter the process
// snapshot. It lets action completion refresh after a mutation (including a
// partially successful multi-PID action) without needlessly rebuilding the list
// after Explorer, clipboard or diagnostic-only operations.
bool isReadOnlyProcessAction(const ProcessActionId actionId) {
    switch (actionId) {
    case ProcessActionId::kOpenFolder:
    case ProcessActionId::kOpenMemoryOperation:
    case ProcessActionId::kScanHotkeys:
        return true;
    default:
        return false;
    }
}

// beginProcessAction captures the current selection and model snapshot on the
// UI thread, then executes Win32/R0 work away from it. AsyncSnapshotTask drops
// stale completions and cancels delivery when the page closes, so a slow driver
// request cannot freeze or resurrect a closed dock.
void beginProcessAction(
    ProcessViewState& state,
    const ProcessActionId actionId,
    std::vector<DWORD> selectedPids,
    std::vector<ProcessSnapshotRow> snapshotRows,
    std::wstring workingText) {
    if (!state.actionTask) {
        setStatus(state, L"进程操作任务不可用。");
        return;
    }
    if (state.actionTask->running()) {
        setStatus(state, L"另一个进程操作正在后台执行，请等待完成。");
        return;
    }

    setStatus(state, std::move(workingText));
    state.actionTask->request(
        [actionId, selectedPids = std::move(selectedPids), snapshotRows = std::move(snapshotRows)]() mutable {
            ProcessViewActionResult completed{};
            completed.result = executeProcessAction(actionId, selectedPids, snapshotRows);
            completed.refreshRequired = !isReadOnlyProcessAction(actionId);
            return completed;
        },
        [&state](std::uint64_t, std::optional<ProcessViewActionResult>&& completed, std::exception_ptr error) {
            if (error || !completed.has_value()) {
                setStatus(state, L"后台进程操作异常结束。");
                return;
            }

            setStatus(state, completed->result.title + L": " + completed->result.detail);
            if (!completed->result.success) {
                ::MessageBoxW(
                    state.hwnd,
                    completed->result.detail.c_str(),
                    completed->result.title.c_str(),
                    MB_OK | MB_ICONINFORMATION);
            }
            if (completed->refreshRequired) {
                beginProcessRefresh(state);
            }
        });
}

// beginR0Injection captures the approved payload path and target PID before
// moving file I/O and the driver request to the action worker.
void beginR0Injection(
    ProcessViewState& state,
    const bool dllMode,
    std::vector<DWORD> selectedPids,
    std::vector<ProcessSnapshotRow> snapshotRows,
    std::wstring payloadPath) {
    if (!state.actionTask) {
        setStatus(state, L"R0 注入任务不可用。");
        return;
    }
    if (state.actionTask->running()) {
        setStatus(state, L"另一个进程操作正在后台执行，请等待完成。");
        return;
    }

    setStatus(state, dllMode ? L"正在后台执行 R0 DLL 注入…" : L"正在后台读取并执行 R0 Shellcode 注入…");
    state.actionTask->request(
        [dllMode, selectedPids = std::move(selectedPids), snapshotRows = std::move(snapshotRows), payloadPath = std::move(payloadPath)]() mutable {
            ProcessViewActionResult completed{};
            completed.result = dllMode
                ? executeR0ProcessDllInjection(selectedPids, snapshotRows, payloadPath)
                : executeR0ProcessShellcodeInjection(selectedPids, snapshotRows, payloadPath);
            completed.refreshRequired = true;
            return completed;
        },
        [&state](std::uint64_t, std::optional<ProcessViewActionResult>&& completed, std::exception_ptr error) {
            if (error || !completed.has_value()) {
                setStatus(state, L"后台 R0 注入异常结束。");
                return;
            }

            setStatus(state, completed->result.title + L": " + completed->result.detail);
            if (!completed->result.success) {
                ::MessageBoxW(
                    state.hwnd,
                    completed->result.detail.c_str(),
                    completed->result.title.c_str(),
                    MB_OK | MB_ICONINFORMATION);
            }
            beginProcessRefresh(state);
        });
}

// executeMenuItem handles one context-menu command. Inputs are page state and an
// action id. UI-local copy and page creation remain immediate; blocking Win32,
// R0 and file operations are queued through beginProcessAction.
void executeMenuItem(ProcessViewState& state, ProcessActionId actionId) {
    if (actionId == ProcessActionId::kCopyCell || actionId == ProcessActionId::kCopyRow ||
        actionId == ProcessActionId::kCopyVisibleResults || actionId == ProcessActionId::kExportVisibleResults) {
        if (actionId == ProcessActionId::kExportVisibleResults) {
            exportVisibleResults(state);
            return;
        }
        if (actionId == ProcessActionId::kCopyVisibleResults) {
            const bool kCopied = writeClipboardText(state.hwnd, visibleRowsAsText(state));
            setStatus(state, kCopied ? L"已复制全部可见进程结果。" : L"复制失败：当前没有可见结果或剪贴板不可用。");
            return;
        }
        const bool kAllColumns = actionId == ProcessActionId::kCopyRow;
        const std::wstring kText = selectedRowsAsText(state, kAllColumns);
        const bool kCopied = writeClipboardText(state.hwnd, kText);
        setStatus(state, kCopied ? L"已复制选中进程行文本。" : L"复制失败：没有可复制的选中行或剪贴板不可用。");
        return;
    }

    if (actionId == ProcessActionId::kOpenDetails) {
        const std::vector<int> kSelectedIndexes = selectedDisplayIndexes(state);
        if (kSelectedIndexes.size() != 1U ||
            kSelectedIndexes.front() < 0 ||
            static_cast<std::size_t>(kSelectedIndexes.front()) >= state.presentationRows.size()) {
            setStatus(state, L"进程详细信息需要单选一个进程。");
            return;
        }
        const ProcessPresentationRow& selectedRow =
            state.presentationRows[static_cast<std::size_t>(kSelectedIndexes.front())];
        const bool kOpened = openProcessDetailWindow(
            state.hwnd,
            selectedRow.processId,
            selectedRow.creationTime100ns);
        setStatus(state, kOpened ? L"已打开进程详细信息窗口。" : L"进程详细信息窗口创建失败。");
        return;
    }

    if (actionId == ProcessActionId::kOpenMemoryOperation ||
        actionId == ProcessActionId::kOpenImageInFileModule ||
        actionId == ProcessActionId::kOpenNetworkForProcess ||
        actionId == ProcessActionId::kOpenHandlesForProcess ||
        actionId == ProcessActionId::kOpenEtwForProcess ||
        actionId == ProcessActionId::kOpenWindowsForProcess) {
        const std::vector<int> kSelectedIndexes = selectedDisplayIndexes(state);
        if (kSelectedIndexes.size() != 1U || kSelectedIndexes.front() < 0 ||
            static_cast<std::size_t>(kSelectedIndexes.front()) >= state.presentationRows.size()) {
            setStatus(state, L"关联调查需要单选一个进程。");
            return;
        }
        const ProcessPresentationRow& selectedRow =
            state.presentationRows[static_cast<std::size_t>(kSelectedIndexes.front())];
        ksword::core::NavigationRequest request{};
        request.entity.kind = ksword::core::EntityKind::kProcess;
        request.entity.id = selectedRow.processId;
        request.entity.creationTime100ns = selectedRow.creationTime100ns;
        switch (actionId) {
        case ProcessActionId::kOpenMemoryOperation:
            request.target = ksword::core::NavigationTarget::kMemoryOperations;
            break;
        case ProcessActionId::kOpenImageInFileModule:
            if (selectedRow.iconPath.empty()) {
                setStatus(state, L"该进程没有可用的映像路径。");
                return;
            }
            request.target = ksword::core::NavigationTarget::kFileBrowser;
            request.entity.kind = ksword::core::EntityKind::kFile;
            request.entity.text = selectedRow.iconPath;
            break;
        case ProcessActionId::kOpenNetworkForProcess:
            request.target = ksword::core::NavigationTarget::kNetworkConnections;
            break;
        case ProcessActionId::kOpenHandlesForProcess:
            request.target = ksword::core::NavigationTarget::kHandleTable;
            break;
        case ProcessActionId::kOpenEtwForProcess:
            request.target = ksword::core::NavigationTarget::kEtwMonitor;
            break;
        case ProcessActionId::kOpenWindowsForProcess:
            request.target = ksword::core::NavigationTarget::kWindowManager;
            break;
        default:
            return;
        }
        const bool kRouted = ksword::ui::requestEntityNavigation(state.hwnd, request);
        setStatus(state, kRouted ? L"已跳转到关联调查模块。" : L"关联调查模块当前无法接收该实体。");
        return;
    }

    if (actionId == ProcessActionId::kR0InjectDll || actionId == ProcessActionId::kR0InjectShellcode) {
        const std::vector<DWORD> kPids = selectedPids(state);
        if (kPids.size() != 1) {
            setStatus(state, L"R0 注入需要单选一个进程。");
            return;
        }

        const bool kDllMode = actionId == ProcessActionId::kR0InjectDll;
        const std::wstring kPayloadPath = promptOpenPayloadFile(
            state.hwnd,
            kDllMode ? L"DLL 文件 (*.dll)\0*.dll\0所有文件 (*.*)\0*.*\0" : L"Shellcode/二进制文件 (*.*)\0*.*\0",
            kDllMode ? L"选择要注入的 DLL" : L"选择要注入的 Shellcode 二进制文件");
        if (kPayloadPath.empty()) {
            setStatus(state, L"已取消 R0 注入。");
            return;
        }
        if (!confirmR0Injection(state.hwnd, kDllMode ? L"DLL 注入" : L"Shellcode 注入", kPids.front(), kPayloadPath)) {
            setStatus(state, L"用户取消 R0 注入。");
            return;
        }

        beginR0Injection(state, kDllMode, kPids, state.model.rows(), kPayloadPath);
        return;
    }

    beginProcessAction(
        state,
        actionId,
        selectedPids(state),
        state.model.rows(),
        L"正在后台执行进程操作…");
}

// showContextMenu builds and displays the grouped process context menu. Inputs are
// page state and screen coordinates. Processing folds related operations into
// submenus so the full retained ProcessDock action surface stays usable without
// a long root menu; selected command ids are mapped back to ProcessActionId.
void showContextMenu(ProcessViewState& state, POINT screenPoint) {
    const std::vector<DWORD> kPids = selectedPids(state);
    const bool kHasVisibleSelection = !selectedDisplayIndexes(state).empty();
    const bool kHasProcessSelection = !kPids.empty();
    const bool kSingleProcess = kPids.size() == 1;
    const bool kActionRunning = state.actionTask && state.actionTask->running();
    state.activeMenuItems.clear();

    HMENU menu = ::CreatePopupMenu();
    if (!menu) {
        return;
    }

    auto appendAction = [&](HMENU parent, ProcessActionId id, const wchar_t* text, bool enabled) {
        state.activeMenuItems.push_back(ProcessActionMenuItem{ id, text });
        const UINT kCommand = kContextMenuBaseId + static_cast<UINT>(state.activeMenuItems.size() - 1);
        const bool kImmediateAction = id == ProcessActionId::kCopyCell ||
            id == ProcessActionId::kCopyRow ||
            id == ProcessActionId::kCopyVisibleResults ||
            id == ProcessActionId::kExportVisibleResults ||
            id == ProcessActionId::kOpenDetails ||
            id == ProcessActionId::kOpenMemoryOperation ||
            id == ProcessActionId::kOpenImageInFileModule ||
            id == ProcessActionId::kOpenNetworkForProcess ||
            id == ProcessActionId::kOpenHandlesForProcess ||
            id == ProcessActionId::kOpenEtwForProcess ||
            id == ProcessActionId::kOpenWindowsForProcess;
        ::AppendMenuW(parent, MF_STRING | (enabled && (!kActionRunning || kImmediateAction) ? 0U : MF_GRAYED), kCommand, text);
    };
    auto appendPopup = [](HMENU parent, HMENU child, const wchar_t* text) {
        ::AppendMenuW(parent, MF_POPUP, reinterpret_cast<UINT_PTR>(child), text);
    };

    HMENU copyMenu = ::CreatePopupMenu();
    appendAction(copyMenu, ProcessActionId::kCopyCell, L"复制单元格", kHasVisibleSelection);
    appendAction(copyMenu, ProcessActionId::kCopyRow, L"复制行", kHasVisibleSelection);
    appendAction(copyMenu, ProcessActionId::kCopyVisibleResults, L"复制可见结果", !state.visibleRowIndexes.empty());
    appendPopup(menu, copyMenu, L"复制");

    HMENU exportMenu = ::CreatePopupMenu();
    appendAction(exportMenu, ProcessActionId::kExportVisibleResults, L"导出可见结果为 TSV...", !state.visibleRowIndexes.empty());
    appendPopup(menu, exportMenu, L"导出");

    HMENU processMenu = ::CreatePopupMenu();
    appendAction(processMenu, ProcessActionId::kOpenDetails, L"进程详细信息", kSingleProcess);
    appendAction(processMenu, ProcessActionId::kTerminateProcessMultiMethod, L"结束进程(组合方法链)", kHasProcessSelection);
    appendAction(processMenu, ProcessActionId::kTerminateProcessTree, L"结束进程树", kHasProcessSelection);
    appendAction(processMenu, ProcessActionId::kSuspendProcess, L"挂起进程", kHasProcessSelection);
    appendAction(processMenu, ProcessActionId::kResumeProcess, L"恢复进程", kHasProcessSelection);
    appendAction(processMenu, ProcessActionId::kOpenFolder, L"打开所在目录", kSingleProcess);
    appendAction(processMenu, ProcessActionId::kOpenMemoryOperation, L"跳转到内存操作", kSingleProcess);
    appendAction(processMenu, ProcessActionId::kScanHotkeys, L"扫描进程热键", kSingleProcess);

    HMENU efficiencyMenu = ::CreatePopupMenu();
    appendAction(efficiencyMenu, ProcessActionId::kEnableEfficiencyMode, L"开启效率模式", kHasProcessSelection);
    appendAction(efficiencyMenu, ProcessActionId::kDisableEfficiencyMode, L"关闭效率模式", kHasProcessSelection);
    appendPopup(processMenu, efficiencyMenu, L"效率模式");

    HMENU criticalMenu = ::CreatePopupMenu();
    appendAction(criticalMenu, ProcessActionId::kSetCriticalProcess, L"设为关键进程", kHasProcessSelection);
    appendAction(criticalMenu, ProcessActionId::kClearCriticalProcess, L"取消关键进程", kHasProcessSelection);
    appendPopup(processMenu, criticalMenu, L"关键进程");

    HMENU priorityMenu = ::CreatePopupMenu();
    appendAction(priorityMenu, ProcessActionId::kSetPriorityIdle, L"Idle", kHasProcessSelection);
    appendAction(priorityMenu, ProcessActionId::kSetPriorityBelowNormal, L"Below Normal", kHasProcessSelection);
    appendAction(priorityMenu, ProcessActionId::kSetPriorityNormal, L"Normal", kHasProcessSelection);
    appendAction(priorityMenu, ProcessActionId::kSetPriorityAboveNormal, L"Above Normal", kHasProcessSelection);
    appendAction(priorityMenu, ProcessActionId::kSetPriorityHigh, L"High", kHasProcessSelection);
    appendAction(priorityMenu, ProcessActionId::kSetPriorityRealtime, L"Realtime", kHasProcessSelection);
    appendPopup(processMenu, priorityMenu, L"优先级");
    appendPopup(menu, processMenu, L"进程");

    HMENU investigationMenu = ::CreatePopupMenu();
    appendAction(investigationMenu, ProcessActionId::kOpenImageInFileModule, L"在文件模块定位映像", kSingleProcess);
    appendAction(investigationMenu, ProcessActionId::kOpenNetworkForProcess, L"查看关联网络连接", kSingleProcess);
    appendAction(investigationMenu, ProcessActionId::kOpenHandlesForProcess, L"查看进程句柄", kSingleProcess);
    appendAction(investigationMenu, ProcessActionId::kOpenEtwForProcess, L"筛选 ETW 事件", kSingleProcess);
    appendAction(investigationMenu, ProcessActionId::kOpenWindowsForProcess, L"查看进程窗口", kSingleProcess);
    appendPopup(menu, investigationMenu, L"关联调查");

    HMENU r0Menu = ::CreatePopupMenu();
    appendAction(r0Menu, ProcessActionId::kR0TerminateProcess, L"R0结束进程", kHasProcessSelection);
    appendAction(r0Menu, ProcessActionId::kR0TerminateProcessTree, L"R0结束进程树", kHasProcessSelection);
    appendAction(r0Menu, ProcessActionId::kR0SuspendProcess, L"R0挂起进程", kHasProcessSelection);
    appendAction(r0Menu, ProcessActionId::kRefreshPplProtectionLevel, L"刷新PPL保护级别", kHasProcessSelection);

    HMENU pplMenu = ::CreatePopupMenu();
    appendAction(pplMenu, ProcessActionId::kR0SetPplNone, L"关闭进程保护 (0x00)", kHasProcessSelection);
    appendAction(pplMenu, ProcessActionId::kR0SetPplAuthenticode, L"Authenticode (0x11)", kHasProcessSelection);
    appendAction(pplMenu, ProcessActionId::kR0SetPplCodeGen, L"CodeGen (0x21)", kHasProcessSelection);
    appendAction(pplMenu, ProcessActionId::kR0SetPplAntimalware, L"Antimalware (0x31)", kHasProcessSelection);
    appendAction(pplMenu, ProcessActionId::kR0SetPplLsa, L"Lsa (0x41)", kHasProcessSelection);
    appendAction(pplMenu, ProcessActionId::kR0SetPplWindows, L"Windows (0x51)", kHasProcessSelection);
    appendAction(pplMenu, ProcessActionId::kR0SetPplWinTcb, L"WinTcb (0x61)", kHasProcessSelection);
    appendPopup(r0Menu, pplMenu, L"设置PPL(轻量)");

    // Full PP is stronger than PPL from the same signer: PPL processes cannot obtain high-privilege handles from PP processes.
    HMENU ppMenu = ::CreatePopupMenu();
    appendAction(ppMenu, ProcessActionId::kR0SetPpAuthenticode, L"Authenticode (0x12)", kHasProcessSelection);
    appendAction(ppMenu, ProcessActionId::kR0SetPpCodeGen, L"CodeGen (0x22)", kHasProcessSelection);
    appendAction(ppMenu, ProcessActionId::kR0SetPpAntimalware, L"Antimalware (0x32)", kHasProcessSelection);
    appendAction(ppMenu, ProcessActionId::kR0SetPpLsa, L"Lsa (0x42)", kHasProcessSelection);
    appendAction(ppMenu, ProcessActionId::kR0SetPpWindows, L"Windows (0x52)", kHasProcessSelection);
    appendAction(ppMenu, ProcessActionId::kR0SetPpWinTcb, L"WinTcb (0x62)", kHasProcessSelection);
    appendPopup(r0Menu, ppMenu, L"设置PP(完整)");

    HMENU integrityMenu = ::CreatePopupMenu();
    appendAction(integrityMenu, ProcessActionId::kR0SetIntegrityUntrusted, L"Untrusted (S-1-16-0)", kHasProcessSelection);
    appendAction(integrityMenu, ProcessActionId::kR0SetIntegrityLow, L"Low (S-1-16-4096)", kHasProcessSelection);
    appendAction(integrityMenu, ProcessActionId::kR0SetIntegrityMedium, L"Medium (S-1-16-8192)", kHasProcessSelection);
    appendAction(integrityMenu, ProcessActionId::kR0SetIntegrityMediumPlus, L"Medium Plus (S-1-16-8448)", kHasProcessSelection);
    appendAction(integrityMenu, ProcessActionId::kR0SetIntegrityHigh, L"High (S-1-16-12288)", kHasProcessSelection);
    appendAction(integrityMenu, ProcessActionId::kR0SetIntegritySystem, L"System (S-1-16-16384)", kHasProcessSelection);
    appendPopup(r0Menu, integrityMenu, L"设置完整性");

    HMENU hideMenu = ::CreatePopupMenu();
    appendAction(hideMenu, ProcessActionId::kR0HideUnlinkOnly, L"只断链", kHasProcessSelection);
    appendAction(hideMenu, ProcessActionId::kR0HidePatchPidOnly, L"只改PID", kHasProcessSelection);
    appendAction(hideMenu, ProcessActionId::kR0HideLegacyBoth, L"改PID+断链(旧版高风险)", kHasProcessSelection);
    appendAction(hideMenu, ProcessActionId::kR0UnhideProcess, L"取消隐藏选中进程", kHasProcessSelection);
    appendAction(hideMenu, ProcessActionId::kR0ClearHiddenMarks, L"清空全部隐藏标记", true);
    appendPopup(r0Menu, hideMenu, L"进程隐藏");

    HMENU specialMenu = ::CreatePopupMenu();
    appendAction(specialMenu, ProcessActionId::kR0EnableBreakOnTermination, L"启用 BreakOnTermination", kHasProcessSelection);
    appendAction(specialMenu, ProcessActionId::kR0DisableBreakOnTermination, L"关闭 BreakOnTermination", kHasProcessSelection);
    appendAction(specialMenu, ProcessActionId::kR0DisableApcInsertion, L"禁止APC插入(现有线程)", kHasProcessSelection);
    appendAction(specialMenu, ProcessActionId::kR0DkomRemoveFromCidTable, L"DKOM从PspCidTable删除", kHasProcessSelection);
    appendPopup(r0Menu, specialMenu, L"特殊/DKOM");

    HMENU injectMenu = ::CreatePopupMenu();
    appendAction(injectMenu, ProcessActionId::kR0InjectDll, L"DLL 注入...", kSingleProcess);
    appendAction(injectMenu, ProcessActionId::kR0InjectShellcode, L"Shellcode 注入...", kSingleProcess);
    appendPopup(r0Menu, injectMenu, L"注入(需确认)");
    appendPopup(menu, r0Menu, L"R0");

    if (!kHasVisibleSelection && !kHasProcessSelection) {
        ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
        ::AppendMenuW(menu, MF_GRAYED, 0, L"未选择进程");
    }

    const UINT kCommand = ::TrackPopupMenu(menu,
        TPM_RETURNCMD | TPM_RIGHTBUTTON,
        screenPoint.x,
        screenPoint.y,
        0,
        state.hwnd,
        nullptr);
    ::DestroyMenu(menu);

    if (kCommand >= kContextMenuBaseId) {
        const std::size_t kIndex = static_cast<std::size_t>(kCommand - kContextMenuBaseId);
        if (kIndex < state.activeMenuItems.size()) {
            executeMenuItem(state, state.activeMenuItems[kIndex].id);
        }
    }
}

// createChildControls creates toolbar buttons, status text and the ListView.
// Input is state with hwnd set. Processing also attaches the image list and
// inserts initial columns. No value is returned; missing HWNDs are tolerated by
// later null checks.
void createChildControls(ProcessViewState& state) {
    state.refreshButton = ksword::ui::createButton(state.hwnd, kRefreshButtonId, L"刷新", 0, 0, 0, 0);
    state.pauseButton = ksword::ui::createButton(state.hwnd, kPauseButtonId, L"暂停", 0, 0, 0, 0);
    state.presetCombo = ::CreateWindowExW(0, WC_COMBOBOXW, L"",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | CBS_DROPDOWNLIST | CBS_HASSTRINGS | WS_VSCROLL,
        0, 0, 0, 0, state.hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kPresetComboId)),
        ::GetModuleHandleW(nullptr), nullptr);
    if (state.presetCombo) {
        ::SendMessageW(state.presetCombo, WM_SETFONT, reinterpret_cast<WPARAM>(ksword::ui::systemUiFont()), TRUE);
        for (ProcessViewPreset preset : { ProcessViewPreset::kMonitor, ProcessViewPreset::kDetail, ProcessViewPreset::kMemory, ProcessViewPreset::kDiskIo, ProcessViewPreset::kGpu, ProcessViewPreset::kSecurity, ProcessViewPreset::kKernel }) {
            const LRESULT kItem = ::SendMessageW(state.presetCombo, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(processViewPresetTitle(preset)));
            ::SendMessageW(state.presetCombo, CB_SETITEMDATA, kItem, static_cast<LPARAM>(preset));
        }
        ::SendMessageW(state.presetCombo, CB_SETCURSEL, 0, 0);
    }
    state.columnsButton = ksword::ui::createButton(state.hwnd, kColumnsButtonId, L"列", 0, 0, 0, 0);
    state.pickerButton = ksword::ui::createButton(state.hwnd, kPickerButtonId, L"拖动选中进程", 0, 0, 0, 0);
    state.refreshSlider = ::CreateWindowExW(0,
        TRACKBAR_CLASSW,
        L"",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | TBS_AUTOTICKS | TBS_TOOLTIPS,
        0,
        0,
        0,
        0,
        state.hwnd,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(kRefreshSliderId)),
        ::GetModuleHandleW(nullptr),
        nullptr);
    if (state.refreshSlider) {
        ::SendMessageW(state.refreshSlider, TBM_SETRANGE, TRUE, MAKELPARAM(1, 10));
        ::SendMessageW(state.refreshSlider, TBM_SETTICFREQ, 1, 0);
        ::SendMessageW(state.refreshSlider, TBM_SETPOS, TRUE, state.refreshIntervalSeconds);
    }
    state.statusText = ksword::ui::createText(state.hwnd, kStatusTextId, L"准备枚举进程。", 0, 0, 0, 0);
    state.filterBar = ksword::ui::createFilterBar(state.hwnd, kFilterBarId, L"筛选进程、PID、路径和 R0 证据", 0, 0, 0, 0);
    state.listView = createProcessListView(state.hwnd, kProcessListId);
    state.imageList = createIconList();
    if (state.listView && state.imageList) {
        ListView_SetImageList(state.listView, state.imageList, LVSIL_SMALL);
    }
    updateToolbarTexts(state);
    rebuildColumns(state);
}

// handleListNotify processes ListView notifications. Inputs are page state and
// NMHDR. Processing supports custom first-column drawing, right-click selection
// correction and context menus; output carries both handled state and LRESULT.
NotifyResult handleListNotify(ProcessViewState& state, NMHDR* header) {
    if (!header) {
        return {};
    }

    // The header right-click and the toolbar 'Columns' button share the same grouped column menu to prevent divergence in show/hide states.
    if (header->hwndFrom == ListView_GetHeader(state.listView)) {
        if (header->code == NM_RCLICK) {
            showColumnChooser(state);
            return { true, 0 };
        }
        return {};
    }
    if (header->hwndFrom != state.listView) return {};

    if (header->code == LVN_GETDISPINFOW) {
        return { true, handleVirtualListDisplayInfo(state, reinterpret_cast<NMLVDISPINFOW*>(header)) };
    }

    if (header->code == NM_CUSTOMDRAW) {
        return { true, handleListCustomDraw(state, reinterpret_cast<NMLVCUSTOMDRAW*>(header)) };
    }

    if (header->code == NM_RCLICK) {
        POINT screenPoint{};
        ::GetCursorPos(&screenPoint);
        POINT clientPoint = screenPoint;
        ::ScreenToClient(state.listView, &clientPoint);

        LVHITTESTINFO hit{};
        hit.pt = clientPoint;
        const int kItem = ListView_HitTest(state.listView, &hit);
        if (groupHeaderAtListItem(state, kItem)) {
            return { true, 0 };
        }
        if (kItem >= 0 && (ListView_GetItemState(state.listView, kItem, LVIS_SELECTED) & LVIS_SELECTED) == 0) {
            ListView_SetItemState(state.listView, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
            ListView_SetItemState(state.listView, kItem, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
        }
        showContextMenu(state, screenPoint);
        return { true, 0 };
    }

    if (header->code == NM_CLICK || header->code == NM_DBLCLK) {
        const auto* activate = reinterpret_cast<const NMITEMACTIVATE*>(header);
        if (!activate || activate->iItem < 0) {
            return {};
        }
        const ProcessPresentationRow* group = groupHeaderAtListItem(state, activate->iItem);
        if (group) {
            const ProcessFriendlyGroup kGroupId = group->display.group;
            state.model.toggleGroupCollapsed(kGroupId);
            rebuildRows(state);
            setStatus(state, state.model.isGroupCollapsed(kGroupId) ? L"已折叠进程分组。" : L"已展开进程分组。");
            return { true, 0 };
        }
    }

    return {};
}

// processViewWndProc dispatches page messages. Inputs are standard Win32 window
// procedure parameters. Processing owns state lifetime, child layout, refresh,
// view switching, drag-picker completion and context menus. Output is an LRESULT
// compatible with DefWindowProcW.
LRESULT CALLBACK processViewWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (msg == WM_NCCREATE) {
        auto state = std::make_unique<ProcessViewState>();
        state->hwnd = hwnd;
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(state.release()));
    }

    ProcessViewState* state = stateFromWindow(hwnd);
    switch (msg) {
    case WM_CREATE:
        if (state) {
            createChildControls(*state);
            state->refreshTask = std::make_unique<ksword::ui::AsyncSnapshotTask<ProcessRefreshSnapshot>>(hwnd, kMsgRefreshCompleted);
            state->filterTask = std::make_unique<ksword::ui::AsyncSnapshotTask<ProcessFilterResult>>(hwnd, kMsgFilterCompleted);
            state->actionTask = std::make_unique<ksword::ui::AsyncSnapshotTask<ProcessViewActionResult>>(hwnd, kMsgActionCompleted);
            setStatus(*state, L"进程页已创建，等待首次异步刷新。");
            ::PostMessageW(hwnd, kMsgInitialRefresh, 0, 0);
        }
        return 0;
    case kMsgInitialRefresh:
    case kMsgRequestRefresh:
        if (state) {
            beginProcessRefresh(*state);
            restartRefreshTimer(*state);
        }
        return 0;
    case kMsgOpenDetails:
        if (state && lParam != 0) {
            const auto* request = reinterpret_cast<const ExternalDetailRequest*>(lParam);
            const ULONGLONG kCreationTime = resolveCurrentProcessCreationTime(
                *state, request->processId, request->expectedCreationTime100ns);
            if (kCreationTime != 0U && openProcessDetailWindow(hwnd, request->processId, kCreationTime)) {
                setStatus(*state, L"已按稳定进程身份打开详细信息窗口。");
                return TRUE;
            }
            setStatus(*state, L"无法确认当前 PID 对应的进程实例，已拒绝跨页打开。");
        }
        return FALSE;
    case kMsgRefreshCompleted:
        if (state && state->refreshTask && state->refreshTask->consume(hwnd, wParam, lParam)) {
            return 0;
        }
        break;
    case kMsgFilterCompleted:
        if (state && state->filterTask && state->filterTask->consume(hwnd, wParam, lParam)) {
            return 0;
        }
        break;
    case kMsgActionCompleted:
        if (state && state->actionTask && state->actionTask->consume(hwnd, wParam, lParam)) {
            return 0;
        }
        break;
    case WM_SIZE:
        if (state) {
            RECT rc{};
            ::GetClientRect(hwnd, &rc);
            layoutChildren(*state, rc);
        }
        return 0;
    case WM_COMMAND:
        if (state && LOWORD(wParam) == kFilterBarId && HIWORD(wParam) == EN_CHANGE) {
            requestProcessFilter(*state,
                ksword::ui::getFilterBarText(state->filterBar),
                selectedStableKeys(*state),
                stableKeyFromListItem(*state, ListView_GetTopIndex(state->listView)));
            return 0;
        }
        if (state && HIWORD(wParam) == BN_CLICKED) {
            switch (LOWORD(wParam)) {
            case kRefreshButtonId:
                beginProcessRefresh(*state);
                return 0;
            case kColumnsButtonId: {
                showColumnChooser(*state);
                return 0;
            }
            case kPauseButtonId:
                toggleRefreshPaused(*state);
                return 0;
            case kPickerButtonId:
                beginPicker(*state);
                return 0;
            default:
                break;
            }
        }
        if (state && LOWORD(wParam) == kPresetComboId && HIWORD(wParam) == CBN_SELCHANGE) {
            const LRESULT kSelected = ::SendMessageW(state->presetCombo, CB_GETCURSEL, 0, 0);
            const LRESULT kValue = kSelected >= 0 ? ::SendMessageW(state->presetCombo, CB_GETITEMDATA, kSelected, 0) : -1;
            if (kValue >= 0) applyPreset(*state, static_cast<ProcessViewPreset>(kValue));
            return 0;
        }
        break;
    case WM_TIMER:
        if (state && wParam == kRefreshTimerId) {
            if (state->refreshPaused) {
                return 0;
            }
            if ((::GetAsyncKeyState(VK_LCONTROL) & 0x8000) != 0) {
                setStatus(*state, L"左 Ctrl 按下，跳过本次自动刷新。");
                return 0;
            }
            beginProcessRefresh(*state);
            return 0;
        }
        break;
    case WM_HSCROLL:
        if (state && reinterpret_cast<HWND>(lParam) == state->refreshSlider) {
            const LRESULT kPos = ::SendMessageW(state->refreshSlider, TBM_GETPOS, 0, 0);
            state->refreshIntervalSeconds = static_cast<UINT>(std::clamp<LRESULT>(kPos, 1, 10));
            restartRefreshTimer(*state);
            setStatus(*state, L"自动刷新频率: " + std::to_wstring(state->refreshIntervalSeconds) + L"s。");
            return 0;
        }
        break;
    case WM_NOTIFY:
        if (state) {
            const NotifyResult kNotify = handleListNotify(*state, reinterpret_cast<NMHDR*>(lParam));
            if (kNotify.handled) {
                return kNotify.result;
            }
        }
        break;
    case WM_CONTEXTMENU:
        if (state && reinterpret_cast<HWND>(wParam) == state->listView) {
            POINT pt{ GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam) };
            if (pt.x != -1 || pt.y != -1) {
                return 0;
            }
            RECT rc{};
            ::GetWindowRect(state->listView, &rc);
            pt.x = rc.left + 24;
            pt.y = rc.top + 24;
            showContextMenu(*state, pt);
            return 0;
        }
        break;
    case WM_LBUTTONUP:
        if (state && state->pickingWindow) {
            completePicker(*state);
            return 0;
        }
        break;
    case WM_KEYDOWN:
        if (state && state->pickingWindow && wParam == VK_ESCAPE) {
            state->pickingWindow = false;
            if (::GetCapture() == hwnd) {
                ::ReleaseCapture();
            }
            setStatus(*state, L"拖动选中进程已取消。");
            return 0;
        }
        break;
    case WM_SETCURSOR:
        if (state && state->pickingWindow) {
            ::SetCursor(::LoadCursorW(nullptr, IDC_CROSS));
            return TRUE;
        }
        break;
    case WM_CAPTURECHANGED:
        if (state && state->pickingWindow && reinterpret_cast<HWND>(lParam) != hwnd) {
            state->pickingWindow = false;
            setStatus(*state, L"拖动选中进程已取消。");
        }
        break;
    case WM_CTLCOLORSTATIC: {
        HDC dc = reinterpret_cast<HDC>(wParam);
        ::SetBkMode(dc, TRANSPARENT);
        ::SetTextColor(dc, ksword::ui::appTheme().textColor);
        return reinterpret_cast<LRESULT>(ksword::ui::appTheme().windowBrush());
    }
    case WM_PAINT: {
        PAINTSTRUCT ps{};
        HDC dc = ::BeginPaint(hwnd, &ps);
        paintBackground(hwnd, dc);
        ::EndPaint(hwnd, &ps);
        return 0;
    }
    case WM_ERASEBKGND:
        return 1;
    case WM_NCDESTROY:
        if (state) {
            ::KillTimer(hwnd, kRefreshTimerId);
            if (state->refreshTask) {
                state->refreshTask->cancel();
            }
            if (state->filterTask) {
                state->filterTask->cancel();
            }
            if (state->actionTask) {
                state->actionTask->cancel();
            }
            if (state->imageList) {
                ImageList_Destroy(state->imageList);
                state->imageList = nullptr;
            }
            delete state;
            ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
        }
        break;
    default:
        break;
    }

    return ::DefWindowProcW(hwnd, msg, wParam, lParam);
}

// registerProcessViewClass installs the custom process page class once. There
// are no inputs; processing registers WNDCLASSW and accepts an existing class;
// output is true when CreateWindowExW can use the class name.
bool registerProcessViewClass() {
    static bool registered = false;
    if (registered) {
        return true;
    }

    WNDCLASSW wc{};
    wc.lpfnWndProc = processViewWndProc;
    wc.hInstance = ::GetModuleHandleW(nullptr);
    wc.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = ksword::ui::appTheme().windowBrush();
    wc.lpszClassName = kProcessViewClass;
    if (::RegisterClassW(&wc) || ::GetLastError() == ERROR_CLASS_ALREADY_EXISTS) {
        registered = true;
    }
    return registered;
}

} // namespace

HWND createProcessView(HWND parent, const RECT& bounds) {
    if (!registerProcessViewClass()) {
        return nullptr;
    }

    return ::CreateWindowExW(0,
        kProcessViewClass,
        L"Process List",
        WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN | WS_CLIPSIBLINGS,
        bounds.left,
        bounds.top,
        bounds.right - bounds.left,
        bounds.bottom - bounds.top,
        parent,
        nullptr,
        ::GetModuleHandleW(nullptr),
        nullptr);
}

void resizeProcessView(HWND view, const RECT& bounds) {
    if (view) {
        ::MoveWindow(view,
            bounds.left,
            bounds.top,
            bounds.right - bounds.left,
            bounds.bottom - bounds.top,
            TRUE);
    }
}

void requestProcessViewRefresh(HWND view) {
    if (view) {
        // view usage: Created process page window; PostMessage avoids synchronous blocking of the main window by driver state callbacks.
        ::PostMessageW(view, kMsgRequestRefresh, 0, 0);
    }
}

bool requestProcessViewOpenDetails(HWND view, DWORD processId, ULONGLONG expectedCreationTime100ns) {
    if (!view || processId == 0) {
        return false;
    }
    const ExternalDetailRequest kRequest{ processId, expectedCreationTime100ns };
    return ::SendMessageW(view, kMsgOpenDetails, 0, reinterpret_cast<LPARAM>(&kRequest)) != 0;
}

} // namespace Ksword::Features::Process

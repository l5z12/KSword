#include "HandlePage.h"

#include "HandleClient.h"

#include "../../core/Common.h"
#include "../../core/EntityRef.h"

#include "../../ui/AsyncTask.h"
#include "../../ui/Controls.h"
#include "../../ui/EntityNavigation.h"
#include "../../ui/FilterBar.h"
#include "../../ui/ExportUtil.h"
#include "../../ui/ListViewUtil.h"
#include "../../ui/LoadingOverlay.h"
#include "../../ui/TabUtil.h"
#include "../../ui/Theme.h"
#include "../../ui/VirtualListView.h"

#include "../../../../shared/driver/KswordArkHandleIoctl.h"

#include <commctrl.h>
#include <windowsx.h>

#include <algorithm>
#include <cstring>
#include <cstdlib>
#include <cwctype>
#include <cstdint>
#include <iomanip>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

namespace ksword::features::handle {

constexpr wchar_t kHandlePageClass[] = L"KswordARKLight.HandlePage";
constexpr int kPidEditId = 57001;
constexpr int kRefreshButtonId = 57002;
constexpr int kStatusTextId = 57003;
constexpr int kTabId = 57004;
constexpr int kHandleListId = 57005;
constexpr int kDetailListId = 57006;
constexpr int kFilterBarId = 57007;
constexpr int kLoadingOverlayId = 57008;
constexpr int kHandleTabIndex = 0;
constexpr int kDetailTabIndex = 1;
constexpr UINT kHandleMenuCopyCell = 57101;
constexpr UINT kHandleMenuCopyRow = 57102;
constexpr UINT kHandleMenuCopyVisible = 57103;
constexpr UINT kHandleMenuOpenProcessDetails = 57104;
constexpr UINT kHandleMenuExportVisible = 57105;
constexpr UINT kMsgHandleRefreshCompleted = WM_APP + 574;
constexpr UINT kMsgHandleFilterCompleted = WM_APP + 575;
constexpr UINT kMsgHandleDetailCompleted = WM_APP + 576;
constexpr UINT kMsgExternalProcess = WM_APP + 577;

struct HandleFilterResult {
    std::uint64_t snapshotGeneration = 0;
    std::wstring query;
    bool useRegex = false;
    std::wstring selectedStableKey;
    std::wstring topStableKey;
    std::vector<std::size_t> visibleIndexes;
};

struct HandleRefreshSnapshot {
    std::uint32_t processId = 0;
    std::uint64_t processCreationTime100ns = 0;
    bool identityMatched = false;
    HandleEnumView enumeration;
    std::vector<ksword::ui::VirtualListRow> rows;
};

struct HandleDetailTaskResult {
    std::uint64_t snapshotGeneration = 0;
    std::uint32_t processId = 0;
    std::uint64_t processCreationTime100ns = 0;
    std::uint64_t handleValue = 0;
    bool identityMatched = false;
    HandleObjectDetailView detail;
};

// HandlePageState stores query snapshots separately from HWND fields so the
// public header remains compact. Inputs are written by Refresh/populateDetail;
// output behavior is value ownership for page lifetime.
struct HandlePageState {
    HandleEnumView snapshot;
    std::uint32_t snapshotProcessId = 0;
    std::uint64_t snapshotProcessCreationTime100ns = 0;
    HandleObjectDetailView detail;
    ksword::ui::VirtualListView handleList;
    std::shared_ptr<const std::vector<ksword::ui::VirtualListRow>> filterRows;
    std::uint64_t snapshotGeneration = 0;
    std::wstring filterQuery;
    bool filterUseRegex = false;
    int contextColumn = 0;
    std::unique_ptr<ksword::ui::AsyncSnapshotTask<HandleRefreshSnapshot>> refreshTask;
    std::unique_ptr<ksword::ui::AsyncSnapshotTask<HandleFilterResult>> filterTask;
    std::unique_ptr<ksword::ui::AsyncSnapshotTask<HandleDetailTaskResult>> detailTask;
};

namespace {

// Width returns a non-negative RECT width. Input is any RECT; output is pixels.
int width(const RECT& rect) {
    return rect.right > rect.left ? rect.right - rect.left : 0;
}

// Height returns a non-negative RECT height. Input is any RECT; output is pixels.
int height(const RECT& rect) {
    return rect.bottom > rect.top ? rect.bottom - rect.top : 0;
}

// Hex32 formats 32-bit diagnostics. Input is an integer; output is uppercase
// hexadecimal with 0x prefix for table display.
std::wstring hex32(const std::uint32_t value) {
    std::wostringstream stream;
    stream << L"0x" << std::uppercase << std::hex << std::setw(8) << std::setfill(L'0') << value;
    return stream.str();
}

// Hex64 formats pointer-sized or 64-bit diagnostics. Input is an integer;
// output is uppercase hexadecimal with fixed 16-digit width.
std::wstring hex64(const std::uint64_t value) {
    std::wostringstream stream;
    stream << L"0x" << std::uppercase << std::hex << std::setw(16) << std::setfill(L'0') << value;
    return stream.str();
}

// ntStatusText formats signed NTSTATUS values as unsigned hex. Input is the
// status integer; output keeps success/failure codes readable.
std::wstring ntStatusText(const long status) {
    return hex32(static_cast<std::uint32_t>(status));
}

// utf8ToWide converts ArkDriverClient diagnostic strings to UTF-16. Input is a
// narrow string that is normally ASCII; processing uses byte-preserving widening;
// output is safe for Win32 controls.
std::wstring utf8ToWide(const std::string& text) {
    std::wstring wide;
    wide.reserve(text.size());
    for (const unsigned char kCh : text) {
        wide.push_back(static_cast<wchar_t>(kCh));
    }
    return wide;
}

// tryReadProcessCreationTime100ns returns the immutable process creation time
// from an already-opened process handle. The caller retains that handle while a
// PID-addressed driver request is in flight, preventing PID reuse.
bool tryReadProcessCreationTime100ns(HANDLE process, std::uint64_t& creationTime100nsOut) {
    creationTime100nsOut = 0;
    if (!process) {
        return false;
    }
    FILETIME creationTime{};
    FILETIME exitTime{};
    FILETIME kernelTime{};
    FILETIME userTime{};
    if (!::GetProcessTimes(process, &creationTime, &exitTime, &kernelTime, &userTime)) {
        return false;
    }
    creationTime100nsOut =
        (static_cast<std::uint64_t>(creationTime.dwHighDateTime) << 32U) |
        static_cast<std::uint64_t>(creationTime.dwLowDateTime);
    return creationTime100nsOut != 0U;
}

// BoolText returns a Chinese yes/no label. Input is a boolean; output is a
// stable UI string.
const wchar_t* boolText(const bool value) {
    return value ? L"是" : L"否";
}

// decodeStatusText maps handle-table decode status to readable labels. Input is
// KSWORD_ARK_HANDLE_DECODE_STATUS_*; output is a static UI label.
const wchar_t* decodeStatusText(const std::uint32_t status) {
    switch (status) {
    case KSWORD_ARK_HANDLE_DECODE_STATUS_OK: return L"OK";
    case KSWORD_ARK_HANDLE_DECODE_STATUS_PARTIAL: return L"Partial";
    case KSWORD_ARK_HANDLE_DECODE_STATUS_DYNDATA_MISSING: return L"DynData缺失";
    case KSWORD_ARK_HANDLE_DECODE_STATUS_PROCESS_LOOKUP_FAILED: return L"进程查找失败";
    case KSWORD_ARK_HANDLE_DECODE_STATUS_PROCESS_EXITING: return L"进程退出中";
    case KSWORD_ARK_HANDLE_DECODE_STATUS_HANDLE_TABLE_MISSING: return L"HandleTable缺失";
    case KSWORD_ARK_HANDLE_DECODE_STATUS_OBJECT_DECODE_FAILED: return L"对象解码失败";
    case KSWORD_ARK_HANDLE_DECODE_STATUS_TYPE_DECODE_FAILED: return L"类型解码失败";
    case KSWORD_ARK_HANDLE_DECODE_STATUS_READ_FAILED: return L"读取失败";
    case KSWORD_ARK_HANDLE_DECODE_STATUS_BUFFER_TOO_SMALL: return L"缓冲区不足";
    case KSWORD_ARK_HANDLE_DECODE_STATUS_HEADER_DYNDATA_MISSING: return L"ObjectHeader偏移缺失";
    case KSWORD_ARK_HANDLE_DECODE_STATUS_HEADER_READ_FAILED: return L"ObjectHeader读取失败";
    case KSWORD_ARK_HANDLE_DECODE_STATUS_ACCESS_DECODE_FAILED: return L"访问掩码解码失败";
    default: return L"Unavailable";
    }
}

// queryStatusText maps object-query status to readable labels. Input is
// KSWORD_ARK_OBJECT_QUERY_STATUS_*; output is a static UI label.
const wchar_t* queryStatusText(const std::uint32_t status) {
    switch (status) {
    case KSWORD_ARK_OBJECT_QUERY_STATUS_OK: return L"OK";
    case KSWORD_ARK_OBJECT_QUERY_STATUS_PARTIAL: return L"Partial";
    case KSWORD_ARK_OBJECT_QUERY_STATUS_DYNDATA_MISSING: return L"DynData缺失";
    case KSWORD_ARK_OBJECT_QUERY_STATUS_PROCESS_LOOKUP_FAILED: return L"进程查找失败";
    case KSWORD_ARK_OBJECT_QUERY_STATUS_HANDLE_REFERENCE_FAILED: return L"句柄引用失败";
    case KSWORD_ARK_OBJECT_QUERY_STATUS_TYPE_QUERY_FAILED: return L"类型查询失败";
    case KSWORD_ARK_OBJECT_QUERY_STATUS_NAME_QUERY_FAILED: return L"名称查询失败";
    case KSWORD_ARK_OBJECT_QUERY_STATUS_NAME_TRUNCATED: return L"名称截断";
    case KSWORD_ARK_OBJECT_QUERY_STATUS_HEADER_DYNDATA_MISSING: return L"ObjectHeader偏移缺失";
    case KSWORD_ARK_OBJECT_QUERY_STATUS_HEADER_QUERY_FAILED: return L"ObjectHeader查询失败";
    case KSWORD_ARK_OBJECT_QUERY_STATUS_ACCESS_DECODE_FAILED: return L"访问掩码解码失败";
    default: return L"Unavailable";
    }
}

// fieldPresent checks one protocol field flag. Inputs are a flag bitmap and one
// KSWORD_ARK_HANDLE_FIELD_* bit; output says whether the field is present.
bool fieldPresent(const std::uint32_t flags, const std::uint32_t bit) {
    return (flags & bit) != 0U;
}

// detailFieldPresent checks one object-query field flag. Inputs are a flag
// bitmap and one KSWORD_ARK_OBJECT_INFO_FIELD_* bit; output says field presence.
bool detailFieldPresent(const std::uint32_t flags, const std::uint32_t bit) {
    return (flags & bit) != 0U;
}

// fieldText renders a present/missing marker. Input is a boolean; output is a
// short Chinese status value.
std::wstring fieldText(const bool present) {
    return present ? L"Present" : L"Missing";
}

// anomalyText derives read-only risk labels from row diagnostics. Input is a
// parsed handle entry; output is a semicolon-separated label list for UI.
std::wstring anomalyText(const HandleEntryView& entry) {
    std::vector<std::wstring> labels;
    if (entry.decodeStatus != KSWORD_ARK_HANDLE_DECODE_STATUS_OK) {
        labels.push_back(decodeStatusText(entry.decodeStatus));
    }
    if (entry.objectAddress == 0 && fieldPresent(entry.fieldFlags, KSWORD_ARK_HANDLE_FIELD_OBJECT_PRESENT)) {
        labels.push_back(L"对象地址为空");
    }
    if (labels.empty()) {
        return L"";
    }
    std::wstring text;
    for (const std::wstring& label : labels) {
        if (!text.empty()) {
            text += L"; ";
        }
        text += label;
    }
    return text;
}

std::vector<ksword::ui::VirtualListRow> buildVirtualHandleRows(const HandleEnumView& snapshot) {
    std::vector<ksword::ui::VirtualListRow> rows;
    rows.reserve(snapshot.entries.size());
    for (std::size_t index = 0; index < snapshot.entries.size(); ++index) {
        const HandleEntryView& entry = snapshot.entries[index];
        ksword::ui::VirtualListRow row{};
        row.stableKey = std::to_wstring(entry.processId) + L":" + hex32(entry.handleValue);
        row.itemData = static_cast<LPARAM>(index);
        row.cells = {
            std::to_wstring(entry.processId),
            hex32(entry.handleValue),
            hex64(entry.objectAddress),
            L"未公开",
            L"未公开",
            std::to_wstring(entry.objectTypeIndex),
            hex32(entry.grantedAccess),
            hex32(entry.attributes),
            L"未公开",
            L"未公开",
            decodeStatusText(entry.decodeStatus),
            anomalyText(entry),
        };
        // Detail-only diagnostic fields participate in the local snapshot
        // search without adding hidden columns or issuing another IOCTL.
        row.cells.push_back(hex64(entry.dynDataCapabilityMask));
        row.cells.push_back(hex32(entry.epObjectTableOffset));
        row.cells.push_back(hex32(entry.htHandleContentionEventOffset));
        row.cells.push_back(hex32(entry.fieldFlags));
        rows.push_back(std::move(row));
    }
    return rows;
}

// readPidEdit parses the PID edit box. Input is the edit HWND; processing
// accepts decimal text only; output is zero when parsing fails.
std::uint32_t readPidEdit(HWND edit) {
    wchar_t buffer[64]{};
    if (!edit || ::GetWindowTextW(edit, buffer, static_cast<int>(sizeof(buffer) / sizeof(buffer[0]))) <= 0) {
        return 0;
    }
    wchar_t* end = nullptr;
    const unsigned long kValue = std::wcstoul(buffer, &end, 10);
    while (end && *end != L'\0' && iswspace(*end)) {
        ++end;
    }
    if (!end || *end != L'\0' || kValue == 0UL || kValue > 0xFFFFFFFFUL) {
        return 0;
    }
    return static_cast<std::uint32_t>(kValue);
}

// registerHandlePageClass registers the window class once. There is no input;
// processing is idempotent; output reports whether CreateWindowExW may use it.
bool registerHandlePageClass() {
    static bool registered = false;
    if (registered) {
        return true;
    }

    WNDCLASSW wc{};
    wc.lpfnWndProc = HandlePage::windowProc;
    wc.hInstance = ::GetModuleHandleW(nullptr);
    wc.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = ksword::ui::appTheme().windowBrush();
    wc.lpszClassName = kHandlePageClass;
    if (::RegisterClassW(&wc) || ::GetLastError() == ERROR_CLASS_ALREADY_EXISTS) {
        registered = true;
    }
    return registered;
}

// addDetailRow appends one key/value/status row. Inputs are the ListView and
// display cells; processing appends a report row; no value is returned.
void addDetailRow(HWND list, const std::wstring& name, const std::wstring& value, const std::wstring& status) {
    ksword::ui::insertListViewTextRow(list, { name, value, status });
}

// insertDetailColumns initializes the detail table columns. Input is the
// ListView HWND; processing inserts name/value/status columns; no return.
void insertDetailColumns(HWND list) {
    ksword::ui::addListViewColumns(list, {
        { 0, 210, LVCFMT_LEFT, L"字段" },
        { 1, 420, LVCFMT_LEFT, L"值" },
        { 2, 220, LVCFMT_LEFT, L"状态/来源" },
    });
}

bool copyTextToClipboard(HWND owner, const std::wstring& text) {
    return ksword::ui::copyTextToClipboard(owner, text, L"句柄审计");
}

void appendTsvRow(std::wstring& output, const std::vector<std::wstring>& cells) {
    for (std::size_t column = 0; column < cells.size(); ++column) {
        if (column != 0) {
            output.push_back(L'\t');
        }
        for (const wchar_t kCh : cells[column]) {
            output.push_back(kCh == L'\t' || kCh == L'\r' || kCh == L'\n' ? L' ' : kCh);
        }
    }
    output += L"\r\n";
}

std::wstring rowsAsTsv(const HandlePageState& state, const bool allVisible) {
    const HWND kList = state.handleList.hwnd();
    const auto& visible = state.handleList.visibleIndexes();
    const auto& rows = state.handleList.rows();
    std::wstring output;
    for (std::size_t item = 0; item < visible.size(); ++item) {
        if (!allVisible && (!kList || (ListView_GetItemState(kList, static_cast<int>(item), LVIS_SELECTED) & LVIS_SELECTED) == 0)) {
            continue;
        }
        const std::size_t kSource = visible[item];
        if (kSource < rows.size()) {
            appendTsvRow(output, rows[kSource].cells);
        }
    }
    return output;
}

// visibleHandleRowsAsTsv serializes exactly the twelve columns shown in the
// current filtered handle table. Input is the immutable rendered snapshot;
// processing never refreshes, resolves objects, or reads hidden diagnostics.
std::wstring visibleHandleRowsAsTsv(const HandlePageState& state) {
    static const std::vector<std::wstring> kColumnTitles = {
        L"PID", L"Handle", L"Object", L"ObjectHeader", L"ObjectType", L"TypeIdx",
        L"GrantedAccess", L"Attributes", L"PtrCount", L"HandleCount", L"Decode", L"异常句柄标记"
    };
    const auto& visible = state.handleList.visibleIndexes();
    const auto& rows = state.handleList.rows();
    if (visible.empty()) {
        return {};
    }

    std::wstring output;
    appendTsvRow(output, kColumnTitles);
    for (const std::size_t kSource : visible) {
        if (kSource >= rows.size()) {
            return {};
        }
        std::vector<std::wstring> cells(kColumnTitles.size());
        const std::vector<std::wstring>& rowCells = rows[kSource].cells;
        const std::size_t kCount = (std::min)(cells.size(), rowCells.size());
        for (std::size_t column = 0; column < kCount; ++column) {
            cells[column] = rowCells[column];
        }
        appendTsvRow(output, cells);
    }
    return output;
}

std::wstring selectedCellText(const HandlePageState& state) {
    const HWND kList = state.handleList.hwnd();
    const int kSelected = kList ? ListView_GetNextItem(kList, -1, LVNI_SELECTED) : -1;
    const auto& visible = state.handleList.visibleIndexes();
    const auto& rows = state.handleList.rows();
    if (kSelected < 0 || static_cast<std::size_t>(kSelected) >= visible.size()) {
        return {};
    }
    const std::size_t kSource = visible[static_cast<std::size_t>(kSelected)];
    if (kSource >= rows.size() || state.contextColumn < 0 || static_cast<std::size_t>(state.contextColumn) >= rows[kSource].cells.size()) {
        return {};
    }
    return rows[kSource].cells[static_cast<std::size_t>(state.contextColumn)];
}

int selectedSnapshotIndex(const HandlePageState& state) {
    const HWND kList = state.handleList.hwnd();
    const int kSelected = kList ? ListView_GetNextItem(kList, -1, LVNI_SELECTED) : -1;
    const auto& visible = state.handleList.visibleIndexes();
    const auto& rows = state.handleList.rows();
    if (kSelected < 0 || static_cast<std::size_t>(kSelected) >= visible.size()) {
        return -1;
    }
    const std::size_t kSource = visible[static_cast<std::size_t>(kSelected)];
    if (kSource >= rows.size() || rows[kSource].itemData < 0) {
        return -1;
    }
    return static_cast<int>(rows[kSource].itemData);
}

// hasAuditedProcessIdentity accepts only the PID/creation-time pair retained
// from the successful HandleTable snapshot preflight. A PID alone is not
// sufficient because it could have been recycled after enumeration.
bool hasAuditedProcessIdentity(const HandlePageState& state) {
    return state.snapshotProcessId != 0U &&
        state.snapshotProcessCreationTime100ns != 0U;
}

std::wstring stableKeyAtVisibleIndex(const HandlePageState& state, const int visibleIndex) {
    const auto& visible = state.handleList.visibleIndexes();
    const auto& rows = state.handleList.rows();
    if (visibleIndex < 0 || static_cast<std::size_t>(visibleIndex) >= visible.size()) {
        return {};
    }
    const std::size_t kSource = visible[static_cast<std::size_t>(visibleIndex)];
    return kSource < rows.size() ? rows[kSource].stableKey : std::wstring{};
}

} // namespace

HWND HandlePage::create(HWND parent, const RECT& bounds) {
    // Inputs are the dock parent and initial geometry. Processing registers the
    // class and allocates a page instance transferred to WM_NCDESTROY; output is
    // the child HWND or nullptr when registration/window creation fails.
    if (!parent || !registerHandlePageClass()) {
        return nullptr;
    }

    auto* page = new HandlePage();
    HWND hwnd = ::CreateWindowExW(
        0,
        kHandlePageClass,
        L"Handle",
        WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN | WS_CLIPSIBLINGS,
        bounds.left,
        bounds.top,
        bounds.right - bounds.left,
        bounds.bottom - bounds.top,
        parent,
        nullptr,
        ::GetModuleHandleW(nullptr),
        page);
    if (!hwnd) {
        delete page;
    }
    return hwnd;
}

bool HandlePage::setProcessId(HWND page, const DWORD processId) {
    return page && processId != 0 &&
        ::SendMessageW(page, kMsgExternalProcess, static_cast<WPARAM>(processId), 0) != 0;
}

LRESULT CALLBACK HandlePage::windowProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam) {
    // Input is the raw Win32 message. Processing stores the page pointer during
    // WM_NCCREATE and delegates all later messages; output is an LRESULT for the
    // window manager.
    HandlePage* page = reinterpret_cast<HandlePage*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    if (message == WM_NCCREATE) {
        const auto* create = reinterpret_cast<const CREATESTRUCTW*>(lParam);
        page = create ? static_cast<HandlePage*>(create->lpCreateParams) : nullptr;
        if (page) {
            page->hwnd_ = hwnd;
            ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(page));
        }
    }
    if (page) {
        return page->handleMessage(hwnd, message, wParam, lParam);
    }
    return ::DefWindowProcW(hwnd, message, wParam, lParam);
}

bool HandlePage::initialize(HWND hwnd) {
    // Input is the newly created root HWND. Processing creates all controls once
    // and retains both tab pages for the page lifetime; output is false if a
    // critical control cannot be created.
    hwnd_ = hwnd;
    state_ = new HandlePageState();

    pidEdit_ = ::CreateWindowExW(
        WS_EX_CLIENTEDGE,
        L"EDIT",
        L"",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
        0,
        0,
        0,
        0,
        hwnd_,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(kPidEditId)),
        ::GetModuleHandleW(nullptr),
        nullptr);
    refreshButton_ = ksword::ui::createButton(hwnd_, kRefreshButtonId, L"枚举PID句柄", 0, 0, 0, 0);
    statusText_ = ksword::ui::createText(hwnd_, kStatusTextId, L"输入 PID 后刷新；页面只读展示句柄证据。", 0, 0, 0, 0);
    filterBar_ = ksword::ui::createFilterBar(hwnd_, kFilterBarId, L"筛选 PID、句柄、对象、访问、状态和详情", 0, 0, 0, 0);
    tab_ = ksword::ui::createTabControl(hwnd_, kTabId, 0, 0, 0, 0);
    if (!pidEdit_ || !refreshButton_ || !statusText_ || !filterBar_ || !tab_) {
        return false;
    }

    ::SendMessageW(pidEdit_, WM_SETFONT, reinterpret_cast<WPARAM>(ksword::ui::systemUiFont()), TRUE);
    ksword::ui::addTabPage(tab_, kHandleTabIndex, { L"句柄表 cross-view" });
    ksword::ui::addTabPage(tab_, kDetailTabIndex, { L"ObjectHeader / ObjectType" });
    ::SendMessageW(tab_, TCM_SETCURSEL, static_cast<WPARAM>(kHandleTabIndex), 0);
    currentTab_ = kHandleTabIndex;

    if (!state_->handleList.create(tab_, kHandleListId, 0, 0, 0, 0, LVS_SHOWSELALWAYS | LVS_SINGLESEL)) {
        return false;
    }
    handleList_ = state_->handleList.hwnd();
    detailList_ = ksword::ui::createReportListView(tab_, kDetailListId, 0, 0, 0, 0, 0);
    if (!handleList_ || !detailList_) {
        return false;
    }
    state_->handleList.addColumns({
        { 0, 80, LVCFMT_RIGHT, L"PID" },
        { 1, 90, LVCFMT_RIGHT, L"Handle" },
        { 2, 165, LVCFMT_LEFT, L"Object" },
        { 3, 165, LVCFMT_LEFT, L"ObjectHeader" },
        { 4, 165, LVCFMT_LEFT, L"ObjectType" },
        { 5, 70, LVCFMT_RIGHT, L"TypeIdx" },
        { 6, 110, LVCFMT_RIGHT, L"GrantedAccess" },
        { 7, 100, LVCFMT_RIGHT, L"Attributes" },
        { 8, 100, LVCFMT_RIGHT, L"PtrCount" },
        { 9, 100, LVCFMT_RIGHT, L"HandleCount" },
        { 10, 150, LVCFMT_LEFT, L"Decode" },
        { 11, 220, LVCFMT_LEFT, L"异常句柄标记" },
    });
    insertDetailColumns(detailList_);
    ListView_SetExtendedListViewStyle(handleList_, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_GRIDLINES | LVS_EX_LABELTIP);

    addDetailRow(detailList_, L"页面边界", L"只读审计", L"不提供关闭句柄/复制句柄/patch 操作");
    addDetailRow(detailList_, L"输入", L"PID + 选中句柄行", L"R0 重新引用句柄，不信任对象地址作为操作凭据");
    addDetailRow(detailList_, L"字段范围", L"ObjectHeader/ObjectType/GrantedAccess/Attributes/异常标记", L"来自现有 Handle IOCTL");

    loadingOverlay_ = ksword::ui::createLoadingOverlay(tab_, kLoadingOverlayId, { 0, 0, 1, 1 });
    state_->refreshTask = std::make_unique<ksword::ui::AsyncSnapshotTask<HandleRefreshSnapshot>>(hwnd_, kMsgHandleRefreshCompleted);
    state_->filterTask = std::make_unique<ksword::ui::AsyncSnapshotTask<HandleFilterResult>>(hwnd_, kMsgHandleFilterCompleted);
    state_->detailTask = std::make_unique<ksword::ui::AsyncSnapshotTask<HandleDetailTaskResult>>(hwnd_, kMsgHandleDetailCompleted);

    ksword::ui::setWindowFontRecursive(hwnd_);
    layout();
    return true;
}

void HandlePage::layout() {
    // Input is the current root client area. Processing positions the toolbar,
    // tab control and retained child pages; no value is returned.
    if (!hwnd_) {
        return;
    }
    RECT rc{};
    ::GetClientRect(hwnd_, &rc);
    const int kWidth = std::max(100, width(rc));
    const int kHeight = std::max(100, height(rc));
    const int kMargin = 8;
    const int kToolbarHeight = 58;

    ::MoveWindow(pidEdit_, kMargin, kMargin, 120, 24, TRUE);
    ::MoveWindow(refreshButton_, kMargin + 128, kMargin, 112, 24, TRUE);
    ::MoveWindow(statusText_, kMargin + 252, kMargin + 3, std::max(100, kWidth - kMargin - 252), 20, TRUE);
    ::MoveWindow(filterBar_, kMargin, kMargin + 28, std::max(100, kWidth - kMargin * 2), 24, TRUE);

    const int kTabTop = kMargin + kToolbarHeight;
    ::MoveWindow(tab_, kMargin, kTabTop, kWidth - kMargin * 2, kHeight - kTabTop - kMargin, TRUE);
    RECT display = ksword::ui::getTabDisplayRect(tab_);
    ::MoveWindow(handleList_, display.left, display.top, width(display), height(display), TRUE);
    ::MoveWindow(detailList_, display.left, display.top, width(display), height(display), TRUE);
    ::MoveWindow(loadingOverlay_, display.left, display.top, width(display), height(display), TRUE);
    ::ShowWindow(handleList_, currentTab_ == kHandleTabIndex ? SW_SHOW : SW_HIDE);
    ::ShowWindow(detailList_, currentTab_ == kDetailTabIndex ? SW_SHOW : SW_HIDE);
}

void HandlePage::refresh() {
    // Input is the PID text box. The driver query runs on the snapshot worker;
    // the UI keeps the previous immutable list visible while it is refreshed.
    if (!state_) {
        return;
    }
    const std::uint32_t kProcessId = readPidEdit(pidEdit_);
    if (kProcessId == 0U) {
        setStatus(L"请输入有效的十进制 PID。");
        return;
    }

    const bool kFirstLoad = state_->handleList.rows().empty();
    setStatus(state_->refreshTask->running()
        ? L"句柄刷新已排队，等待当前快照完成…"
        : L"正在后台只读枚举 PID " + std::to_wstring(kProcessId) + L" 的 HandleTable…");
    ::EnableWindow(refreshButton_, FALSE);
    if (kFirstLoad) {
        ksword::ui::setLoadingOverlay(loadingOverlay_, true, L"正在加载句柄审计…");
    }
    state_->refreshTask->request(
        [kProcessId] {
            HandleRefreshSnapshot snapshot{};
            snapshot.processId = kProcessId;
            ksword::core::UniqueHandle process(::OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION,
                FALSE,
                kProcessId));
            if (!process.valid() ||
                !tryReadProcessCreationTime100ns(process.get(), snapshot.processCreationTime100ns)) {
                return snapshot;
            }
            snapshot.identityMatched = true;
            // Keep the verified process object alive until the PID-addressed
            // driver enumeration returns, so the PID cannot be recycled.
            snapshot.enumeration = HandleAuditClient{}.enumerateProcessHandles(kProcessId);
            snapshot.rows = buildVirtualHandleRows(snapshot.enumeration);
            return snapshot;
        },
        [this](std::uint64_t, std::optional<HandleRefreshSnapshot>&& snapshot, std::exception_ptr error) {
            if (!state_) {
                return;
            }
            ::EnableWindow(refreshButton_, TRUE);
            ksword::ui::setLoadingOverlay(loadingOverlay_, false);
            if (error || !snapshot.has_value()) {
                setStatus(L"句柄后台枚举异常结束，请检查驱动状态与访问权限。");
                return;
            }
            const bool kIdentityMatched = snapshot->identityMatched;
            const std::uint32_t kSnapshotProcessId = snapshot->processId;
            const std::uint64_t kSnapshotProcessCreationTime100ns = snapshot->processCreationTime100ns;
            state_->snapshot = std::move(snapshot->enumeration);
            state_->snapshotProcessId = kIdentityMatched ? kSnapshotProcessId : 0U;
            state_->snapshotProcessCreationTime100ns = kIdentityMatched
                ? kSnapshotProcessCreationTime100ns
                : 0U;
            state_->filterRows = std::make_shared<std::vector<ksword::ui::VirtualListRow>>(std::move(snapshot->rows));
            ++state_->snapshotGeneration;
            populateList();
            const std::wstring kMessage = utf8ToWide(state_->snapshot.io.message);
            setStatus(kIdentityMatched && state_->snapshot.io.ok
                ? L"句柄枚举完成：返回 " + std::to_wstring(state_->snapshot.entries.size()) + L" 行；" + kMessage
                : L"句柄枚举失败：" + kMessage);
        });
}

void HandlePage::populateList() {
    // Input is the latest immutable handle snapshot. Rendering only installs
    // owner-data rows; local filtering is calculated later on the worker.
    if (!state_ || !handleList_) {
        return;
    }

    const std::wstring kSelectedStableKey = stableKeyAtVisibleIndex(*state_, ListView_GetNextItem(handleList_, -1, LVNI_SELECTED));
    const std::wstring kTopStableKey = stableKeyAtVisibleIndex(*state_, ListView_GetTopIndex(handleList_));
    if (!state_->filterRows) {
        return;
    }
    state_->handleList.setRows(*state_->filterRows);
    requestFilter(filterBar_ ? ksword::ui::getFilterBarText(filterBar_) : state_->filterQuery, kSelectedStableKey, kTopStableKey);
}

void HandlePage::requestFilter(const std::wstring& query, std::wstring selectedStableKey, std::wstring topStableKey) {
    if (!state_ || !state_->filterTask || !state_->filterRows) {
        return;
    }
    state_->filterQuery = query;
    state_->filterUseRegex = ksword::ui::getFilterBarRegexEnabled(filterBar_);
    const std::uint64_t kGeneration = state_->snapshotGeneration;
    const auto kFilterRows = state_->filterRows;
    const bool kUseRegex = state_->filterUseRegex;
    if (selectedStableKey.empty()) {
        selectedStableKey = stableKeyAtVisibleIndex(*state_, ListView_GetNextItem(handleList_, -1, LVNI_SELECTED));
    }
    if (topStableKey.empty()) {
        topStableKey = stableKeyAtVisibleIndex(*state_, ListView_GetTopIndex(handleList_));
    }
    state_->filterTask->request(
        [kFilterRows, kGeneration, kUseRegex, query = state_->filterQuery, selectedStableKey = std::move(selectedStableKey), topStableKey = std::move(topStableKey)]() mutable {
            HandleFilterResult result{};
            result.snapshotGeneration = kGeneration;
            result.query = std::move(query);
            result.useRegex = kUseRegex;
            result.selectedStableKey = std::move(selectedStableKey);
            result.topStableKey = std::move(topStableKey);
            result.visibleIndexes = ksword::ui::VirtualListView::filterRowIndexes(*kFilterRows, result.query, kUseRegex);
            return result;
        },
        [this](std::uint64_t, std::optional<HandleFilterResult>&& result, std::exception_ptr error) {
            if (!state_ || error || !result.has_value()) {
                if (state_) {
                    setStatus(L"句柄筛选异常结束，已保留当前可见结果。");
                }
                return;
            }
            if (result->snapshotGeneration == state_->snapshotGeneration && result->query == state_->filterQuery &&
                result->useRegex == state_->filterUseRegex) {
                state_->handleList.setVisibleIndexes(std::move(result->visibleIndexes));
                const auto& rows = state_->handleList.rows();
                const auto& visible = state_->handleList.visibleIndexes();
                for (std::size_t item = 0; item < visible.size(); ++item) {
                    const std::size_t kSource = visible[item];
                    if (!result->selectedStableKey.empty() && kSource < rows.size() && rows[kSource].stableKey == result->selectedStableKey) {
                        ListView_SetItemState(handleList_, static_cast<int>(item), LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
                    }
                    if (!result->topStableKey.empty() && kSource < rows.size() && rows[kSource].stableKey == result->topStableKey) {
                        ListView_EnsureVisible(handleList_, static_cast<int>(item), FALSE);
                    }
                }
            }
        });
}

void HandlePage::showHandleContextMenu(POINT screenPoint) {
    if (!state_ || !handleList_) {
        return;
    }
    POINT clientPoint = screenPoint;
    ::ScreenToClient(handleList_, &clientPoint);
    LVHITTESTINFO hit{};
    hit.pt = clientPoint;
    const int kItem = ListView_SubItemHitTest(handleList_, &hit);
    if (kItem >= 0) {
        state_->contextColumn = hit.iSubItem;
        ListView_SetItemState(handleList_, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
        ListView_SetItemState(handleList_, kItem, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
    }
    const bool kHasSelection = ListView_GetNextItem(handleList_, -1, LVNI_SELECTED) >= 0;
    HMENU menu = ::CreatePopupMenu();
    if (!menu) {
        return;
    }
    ::AppendMenuW(menu, MF_STRING | (kHasSelection ? 0U : MF_GRAYED), kHandleMenuCopyCell, L"复制单元格");
    ::AppendMenuW(menu, MF_STRING | (kHasSelection ? 0U : MF_GRAYED), kHandleMenuCopyRow, L"复制行");
    ::AppendMenuW(menu, MF_STRING | (!state_->handleList.visibleIndexes().empty() ? 0U : MF_GRAYED), kHandleMenuCopyVisible, L"复制可见结果");
    ::AppendMenuW(menu, MF_STRING | (!state_->handleList.visibleIndexes().empty() ? 0U : MF_GRAYED), kHandleMenuExportVisible, L"导出当前可见句柄 TSV");
    ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    const bool kHasAuditedProcessIdentity = hasAuditedProcessIdentity(*state_);
    ::AppendMenuW(
        menu,
        MF_STRING | (kHasAuditedProcessIdentity ? 0U : MF_GRAYED),
        kHandleMenuOpenProcessDetails,
        L"查看已审计进程详细信息");
    const UINT kCommand = ::TrackPopupMenu(menu, TPM_RETURNCMD | TPM_RIGHTBUTTON, screenPoint.x, screenPoint.y, 0, hwnd_, nullptr);
    ::DestroyMenu(menu);
    if (kCommand == kHandleMenuCopyCell) {
        setStatus(copyTextToClipboard(hwnd_, selectedCellText(*state_)) ? L"已复制单元格。" : L"复制单元格失败。");
    } else if (kCommand == kHandleMenuCopyRow) {
        setStatus(copyTextToClipboard(hwnd_, rowsAsTsv(*state_, false)) ? L"已复制行。" : L"复制行失败。");
    } else if (kCommand == kHandleMenuCopyVisible) {
        setStatus(copyTextToClipboard(hwnd_, rowsAsTsv(*state_, true)) ? L"已复制可见结果。" : L"复制可见结果失败。");
    } else if (kCommand == kHandleMenuExportVisible) {
        const std::wstring kText = visibleHandleRowsAsTsv(*state_);
        if (kText.empty()) {
            setStatus(L"没有可导出的当前可见句柄快照。");
            return;
        }
        std::wstring error;
        switch (ksword::ui::saveUtf8TextFileWithDialog(
            hwnd_, L"handle_visible_snapshot.tsv", L"导出当前可见句柄快照",
            L"TSV (*.tsv)\0*.tsv\0All Files (*.*)\0*.*\0", L"tsv", kText, &error)) {
        case ksword::ui::SaveTextFileResult::kSaved:
            setStatus(L"当前可见句柄快照已导出为 TSV，并已记录到证据会话。");
            break;
        case ksword::ui::SaveTextFileResult::kCancelled:
            setStatus(L"已取消导出当前可见句柄快照。");
            break;
        case ksword::ui::SaveTextFileResult::kFailed:
            setStatus(L"导出当前可见句柄快照失败：" + error);
            break;
        }
    } else if (kCommand == kHandleMenuOpenProcessDetails) {
        // Revalidate after the popup closes so an intervening refresh cannot
        // turn an older PID into a navigation target.
        if (!hasAuditedProcessIdentity(*state_)) {
            setStatus(L"没有可验证的进程身份，无法安全打开进程详细信息。");
            return;
        }
        ksword::core::NavigationRequest request{};
        request.target = ksword::core::NavigationTarget::kProcessDetails;
        request.entity.kind = ksword::core::EntityKind::kProcess;
        request.entity.id = state_->snapshotProcessId;
        request.entity.creationTime100ns = state_->snapshotProcessCreationTime100ns;
        const bool kRouted = ksword::ui::requestEntityNavigation(hwnd_, request);
        setStatus(kRouted
            ? L"已请求打开已审计 PID " + std::to_wstring(state_->snapshotProcessId) + L" 的进程详细信息。"
            : L"进程详细信息页未能接收该已审计进程身份。");
    }
}

void HandlePage::showDetailContextMenu(POINT screenPoint) {
    if (!detailList_) {
        return;
    }
    POINT clientPoint = screenPoint;
    ::ScreenToClient(detailList_, &clientPoint);
    LVHITTESTINFO hit{};
    hit.pt = clientPoint;
    const int kItem = ListView_SubItemHitTest(detailList_, &hit);
    if (kItem >= 0) {
        ListView_SetItemState(detailList_, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
        ListView_SetItemState(detailList_, kItem, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
    }
    const bool kHasSelection = ListView_GetNextItem(detailList_, -1, LVNI_SELECTED) >= 0;
    HMENU menu = ::CreatePopupMenu();
    if (!menu) {
        return;
    }
    ::AppendMenuW(menu, MF_STRING | (kHasSelection ? 0U : MF_GRAYED), kHandleMenuCopyCell, L"复制单元格");
    ::AppendMenuW(menu, MF_STRING | (kHasSelection ? 0U : MF_GRAYED), kHandleMenuCopyRow, L"复制行");
    ::AppendMenuW(menu, MF_STRING, kHandleMenuCopyVisible, L"复制可见结果");
    const UINT kCommand = ::TrackPopupMenu(menu, TPM_RETURNCMD | TPM_RIGHTBUTTON, screenPoint.x, screenPoint.y, 0, hwnd_, nullptr);
    ::DestroyMenu(menu);
    std::wstring text;
    const int kSelected = ListView_GetNextItem(detailList_, -1, LVNI_SELECTED);
    const int kRowCount = ListView_GetItemCount(detailList_);
    if (kCommand == kHandleMenuCopyCell && kSelected >= 0) {
        wchar_t buffer[4096]{};
        ListView_GetItemText(detailList_, kSelected, std::max(0, hit.iSubItem), buffer, static_cast<int>(_countof(buffer)));
        text = buffer;
    } else if (kCommand == kHandleMenuCopyRow && kSelected >= 0) {
        for (int column = 0; column < 3; ++column) {
            wchar_t buffer[4096]{};
            ListView_GetItemText(detailList_, kSelected, column, buffer, static_cast<int>(_countof(buffer)));
            if (column != 0) {
                text.push_back(L'\t');
            }
            text += buffer;
        }
    } else if (kCommand == kHandleMenuCopyVisible) {
        for (int row = 0; row < kRowCount; ++row) {
            for (int column = 0; column < 3; ++column) {
                wchar_t buffer[4096]{};
                ListView_GetItemText(detailList_, row, column, buffer, static_cast<int>(_countof(buffer)));
                if (column != 0) {
                    text.push_back(L'\t');
                }
                text += buffer;
            }
            text += L"\r\n";
        }
    }
    if (kCommand != 0) {
        setStatus(copyTextToClipboard(hwnd_, text) ? L"已复制结果。" : L"复制结果失败。");
    }
}

void HandlePage::populateDetail(const int rowIndex) {
    // Input is a selected snapshot row. Object inspection runs on a separate
    // worker and is discarded when a newer handle snapshot replaces the row.
    if (!state_ || !detailList_ || rowIndex < 0 ||
        rowIndex >= static_cast<int>(state_->snapshot.entries.size())) {
        return;
    }
    const HandleEntryView kEntry = state_->snapshot.entries[static_cast<std::size_t>(rowIndex)];
    const std::uint32_t kSnapshotProcessId = state_->snapshotProcessId;
    const std::uint64_t kSnapshotProcessCreationTime100ns = state_->snapshotProcessCreationTime100ns;
    if (kSnapshotProcessId == 0U ||
        kSnapshotProcessCreationTime100ns == 0U ||
        kEntry.processId != kSnapshotProcessId) {
        setStatus(L"句柄对象详情查询异常结束。");
        return;
    }

    ksword::ui::ScopedListViewRedrawLock lock(detailList_);
    ListView_DeleteAllItems(detailList_);
    addDetailRow(detailList_, L"状态", L"正在后台查询 ObjectHeader/ObjectType…", L"可切换或关闭页面");

    const std::uint64_t kSnapshotGeneration = state_->snapshotGeneration;
    ::SendMessageW(tab_, TCM_SETCURSEL, static_cast<WPARAM>(kDetailTabIndex), 0);
    currentTab_ = kDetailTabIndex;
    layout();
    setStatus(L"正在后台读取句柄 " + hex32(kEntry.handleValue) + L" 的对象详情…");
    state_->detailTask->request(
        [kEntry, kSnapshotGeneration, kSnapshotProcessCreationTime100ns] {
            HandleDetailTaskResult result{};
            result.snapshotGeneration = kSnapshotGeneration;
            result.processId = kEntry.processId;
            result.processCreationTime100ns = kSnapshotProcessCreationTime100ns;
            result.handleValue = kEntry.handleValue;
            ksword::core::UniqueHandle process(::OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION,
                FALSE,
                kEntry.processId));
            std::uint64_t actualProcessCreationTime100ns = 0;
            if (!process.valid() ||
                !tryReadProcessCreationTime100ns(process.get(), actualProcessCreationTime100ns) ||
                actualProcessCreationTime100ns != kSnapshotProcessCreationTime100ns) {
                return result;
            }
            result.identityMatched = true;
            // Keep the verified source process alive while the driver resolves
            // the numeric handle value from its HandleTable.
            result.detail = HandleAuditClient{}.queryHandleObject(kEntry.processId, kEntry.handleValue);
            return result;
        },
        [this, kEntry](std::uint64_t, std::optional<HandleDetailTaskResult>&& result, std::exception_ptr error) {
            if (!state_ || error || !result.has_value() || !result->identityMatched) {
                if (state_) {
                    setStatus(L"句柄对象详情查询异常结束。");
                }
                return;
            }
            if (result->snapshotGeneration != state_->snapshotGeneration ||
                result->processId != kEntry.processId ||
                result->processId != state_->snapshotProcessId ||
                result->processCreationTime100ns != state_->snapshotProcessCreationTime100ns ||
                result->handleValue != kEntry.handleValue) {
                return;
            }
            state_->detail = std::move(result->detail);
            ksword::ui::ScopedListViewRedrawLock redrawLock(detailList_);
            ListView_DeleteAllItems(detailList_);
            const HandleObjectDetailView& detail = state_->detail;
            addDetailRow(detailList_, L"Transport", detail.io.ok ? L"OK" : L"FAIL", utf8ToWide(detail.io.message));
    addDetailRow(detailList_, L"PID", std::to_wstring(kEntry.processId), L"查询输入");
    addDetailRow(detailList_, L"Handle", hex32(kEntry.handleValue), L"查询输入");
    addDetailRow(detailList_, L"QueryStatus", queryStatusText(detail.queryStatus), std::to_wstring(detail.queryStatus));
    addDetailRow(detailList_, L"ObjectName", detail.objectName, L"ArkDriverClient 查询结果");
    addDetailRow(detailList_, L"TypeName", detail.typeName, fieldText(detailFieldPresent(detail.fieldFlags, KSWORD_ARK_OBJECT_INFO_FIELD_TYPE_NAME_PRESENT)));
    addDetailRow(detailList_, L"Object", hex64(detail.objectAddress), fieldText(detailFieldPresent(detail.fieldFlags, KSWORD_ARK_OBJECT_INFO_FIELD_OBJECT_PRESENT)));
            addDetailRow(detailList_, L"ObjectHeader", L"未公开", L"当前 ArkDriverClient 强类型结果未提供该字段");
            addDetailRow(detailList_, L"ObjectType", L"未公开", L"当前 ArkDriverClient 强类型结果未提供该字段");
    addDetailRow(detailList_, L"ObjectTypeIndex", std::to_wstring(detail.objectTypeIndex), L"ArkDriverClient 查询结果");
            addDetailRow(detailList_, L"ObjectHeader 字段", L"未公开", L"等待 ArkDriverClient 强类型接口补齐");
    addDetailRow(detailList_, L"GrantedAccess(enum)", hex32(kEntry.grantedAccess), fieldText(fieldPresent(kEntry.fieldFlags, KSWORD_ARK_HANDLE_FIELD_GRANTED_ACCESS_PRESENT)));
    addDetailRow(detailList_, L"ActualGrantedAccess(query)", hex32(detail.actualGrantedAccess), L"不请求 proxy handle");
    addDetailRow(detailList_, L"HandleAttributes", hex32(kEntry.attributes), fieldText(fieldPresent(kEntry.fieldFlags, KSWORD_ARK_HANDLE_FIELD_ATTRIBUTES_PRESENT)));
    addDetailRow(detailList_, L"FieldFlags", hex32(detail.fieldFlags), L"KSWORD_ARK_OBJECT_INFO_FIELD_*");
    addDetailRow(detailList_, L"DynDataCapabilityMask", hex64(detail.dynDataCapabilityMask), L"capability gated");
    addDetailRow(detailList_, L"OtNameOffset", hex32(detail.otNameOffset), L"_OBJECT_TYPE.Name");
    addDetailRow(detailList_, L"OtIndexOffset", hex32(detail.otIndexOffset), L"_OBJECT_TYPE.Index");
    addDetailRow(detailList_, L"ObjectReferenceStatus", ntStatusText(detail.objectReferenceStatus), L"ObReferenceObjectByHandle 路径");
    addDetailRow(detailList_, L"TypeStatus", ntStatusText(detail.typeStatus), L"类型查询");
    addDetailRow(detailList_, L"NameStatus", ntStatusText(detail.nameStatus), L"名称查询");
    addDetailRow(detailList_, L"ProxyStatus", std::to_wstring(detail.proxyStatus), L"本页未请求 proxy handle");
    addDetailRow(detailList_, L"ProxyHandleReturned", boolText(detail.proxyHandle != 0), hex64(detail.proxyHandle));
            if (detail.alpcQueried) {
                const auto kAddAlpcPort = [&](const wchar_t* relation, const ksword::ark::AlpcPortInfo& port) {
                    addDetailRow(detailList_,
                        std::wstring(L"ALPC ") + relation,
                        port.portName.empty() ? hex64(port.objectAddress) : port.portName,
                        L"object=" + hex64(port.objectAddress) +
                            L"; ownerPid=" + std::to_wstring(port.ownerProcessId) +
                            L"; state=" + std::to_wstring(port.state) +
                            L"; flags=" + hex32(port.flags));
                };
                addDetailRow(detailList_,
                    L"ALPC Transport",
                    detail.alpc.io.ok ? L"OK" : L"FAIL",
                    utf8ToWide(detail.alpc.io.message));
                addDetailRow(detailList_, L"ALPC QueryStatus", std::to_wstring(detail.alpc.queryStatus),
                    L"fieldFlags=" + hex32(detail.alpc.fieldFlags) +
                        L"; capability=" + hex64(detail.alpc.dynDataCapabilityMask));
                kAddAlpcPort(L"Query", detail.alpc.queryPort);
                kAddAlpcPort(L"Connection", detail.alpc.connectionPort);
                kAddAlpcPort(L"Server", detail.alpc.serverPort);
                kAddAlpcPort(L"Client", detail.alpc.clientPort);
            }
            addDetailRow(detailList_, L"异常句柄标记", anomalyText(kEntry), L"只读提示，不做关闭/复制/patch");
            setStatus(L"已读取句柄 " + hex32(kEntry.handleValue) + L" 的 ObjectHeader/ObjectType 详情。");
        });
}

void HandlePage::setStatus(const std::wstring& text) {
    // Input is a status message. Processing updates only the STATIC text control
    // and returns no value.
    if (statusText_) {
        ::SetWindowTextW(statusText_, text.c_str());
    }
}

LRESULT HandlePage::handleMessage(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam) {
    switch (message) {
    case kMsgExternalProcess:
        if (pidEdit_ && wParam != 0) {
            const std::wstring kText = std::to_wstring(static_cast<DWORD>(wParam));
            ::SetWindowTextW(pidEdit_, kText.c_str());
            refresh();
            return TRUE;
        }
        return FALSE;
    case WM_CREATE:
        if (!initialize(hwnd)) {
            return -1;
        }
        return 0;
    case WM_SIZE:
        layout();
        return 0;
    case WM_COMMAND:
        if (LOWORD(wParam) == kFilterBarId && HIWORD(wParam) == EN_CHANGE) {
            requestFilter(ksword::ui::getFilterBarText(filterBar_));
            return 0;
        }
        if (HIWORD(wParam) == BN_CLICKED && LOWORD(wParam) == kRefreshButtonId) {
            refresh();
            return 0;
        }
        if (LOWORD(wParam) == kPidEditId && HIWORD(wParam) == EN_CHANGE) {
            setStatus(L"PID 已更新，点击“枚举PID句柄”刷新。");
            return 0;
        }
        break;
    case kMsgHandleRefreshCompleted:
        if (state_ && state_->refreshTask && state_->refreshTask->consume(hwnd, wParam, lParam)) {
            return 0;
        }
        break;
    case kMsgHandleFilterCompleted:
        if (state_ && state_->filterTask && state_->filterTask->consume(hwnd, wParam, lParam)) {
            return 0;
        }
        break;
    case kMsgHandleDetailCompleted:
        if (state_ && state_->detailTask && state_->detailTask->consume(hwnd, wParam, lParam)) {
            return 0;
        }
        break;
    case WM_NOTIFY: {
        const auto* header = reinterpret_cast<const NMHDR*>(lParam);
        if (header && header->hwndFrom == tab_ && header->code == TCN_SELCHANGE) {
            const LRESULT kSelected = ::SendMessageW(tab_, TCM_GETCURSEL, 0, 0);
            if (kSelected >= 0) {
                currentTab_ = static_cast<int>(kSelected);
            }
            layout();
            return 0;
        }
        if (header && header->hwndFrom == handleList_) {
            LRESULT result = 0;
            if (state_ && state_->handleList.handleNotify(*header, result)) {
                return result;
            }
        }
        if (header && header->hwndFrom == handleList_ &&
            (header->code == NM_DBLCLK || header->code == LVN_ITEMCHANGED)) {
            if (header->code == NM_DBLCLK) {
                populateDetail(state_ ? selectedSnapshotIndex(*state_) : -1);
                return 0;
            }
            const auto* changed = reinterpret_cast<const NMLISTVIEW*>(lParam);
            if (changed && (changed->uNewState & LVIS_SELECTED) != 0 &&
                (changed->uOldState & LVIS_SELECTED) == 0) {
                setStatus(L"已选择句柄；双击行查看 ObjectHeader/ObjectType 详情。");
            }
        }
        break;
    }
    case WM_CONTEXTMENU:
        if (reinterpret_cast<HWND>(wParam) == handleList_) {
            POINT point{ GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam) };
            if (point.x == -1 && point.y == -1) {
                RECT rect{};
                ::GetWindowRect(handleList_, &rect);
                point = { rect.left + 16, rect.top + 16 };
            }
            showHandleContextMenu(point);
            return 0;
        }
        if (reinterpret_cast<HWND>(wParam) == detailList_) {
            POINT point{ GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam) };
            if (point.x == -1 && point.y == -1) {
                RECT rect{};
                ::GetWindowRect(detailList_, &rect);
                point = { rect.left + 16, rect.top + 16 };
            }
            showDetailContextMenu(point);
            return 0;
        }
        break;
    case WM_CTLCOLORSTATIC: {
        HDC dc = reinterpret_cast<HDC>(wParam);
        ::SetBkMode(dc, TRANSPARENT);
        ::SetTextColor(dc, ksword::ui::appTheme().textColor);
        return reinterpret_cast<LRESULT>(ksword::ui::appTheme().windowBrush());
    }
    case WM_ERASEBKGND:
        return 1;
    case WM_NCDESTROY:
        if (state_) {
            if (state_->refreshTask) {
                state_->refreshTask->cancel();
            }
            if (state_->filterTask) {
                state_->filterTask->cancel();
            }
            if (state_->detailTask) {
                state_->detailTask->cancel();
            }
        }
        delete state_;
        state_ = nullptr;
        delete this;
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
        return 0;
    default:
        break;
    }
    return ::DefWindowProcW(hwnd, message, wParam, lParam);
}

} // namespace Ksword::Features::Handle

#include "DriverMemoryView.h"

#include "DriverMemoryClient.h"
#include "DriverMemoryModel.h"
#include "MemoryInspection.h"
#include "MemorySnapshot.h"
#include "MemoryWritePlan.h"
#include "../../ui/AsyncTask.h"
#include "../../ui/Controls.h"
#include "../../ui/ExportUtil.h"
#include "../../ui/FilterBar.h"
#include "../../ui/ListViewUtil.h"
#include "../../ui/TextFindSupport.h"
#include "../../ui/Theme.h"
#include "../../ui/VirtualListView.h"

#include <algorithm>
#include <atomic>
#include <cwchar>
#include <iomanip>
#include <memory>
#include <sstream>
#include <string>
#include <vector>
#include <commctrl.h>
#include <windowsx.h>

namespace ksword::features::memory {
namespace {

constexpr wchar_t kDriverMemoryViewClass[] = L"KswordARKLight.DriverMemoryView";
constexpr int kPidEditId = 51001;
constexpr int kAddressEditId = 51002;
constexpr int kLengthEditId = 51003;
constexpr int kReadButtonId = 51004;
constexpr int kWriteButtonId = 51005;
constexpr int kHexEditId = 51006;
constexpr int kStatusEditId = 51007;
constexpr int kHistoryFilterId = 51008;
constexpr int kHistoryListId = 51009;
constexpr int kSnapshotPreviousButtonId = 51010;
constexpr int kSnapshotNextButtonId = 51011;
constexpr int kPreviewDiffButtonId = 51012;
constexpr int kApplyDiffButtonId = 51013;
constexpr UINT kMemoryMenuRead = 51501;
constexpr UINT kMemoryMenuWrite = 51502;
constexpr UINT kMemoryMenuCopyHex = 51503;
constexpr UINT kMemoryMenuPasteHex = 51504;
constexpr UINT kMemoryMenuClearHex = 51505;
constexpr UINT kMemoryMenuNormalizeHex = 51506;
constexpr UINT kMemoryMenuSelectAll = 51507;
constexpr UINT kMemoryMenuCopyStatus = 51508;
constexpr UINT kMemoryMenuCopyHistoryCell = 51509;
constexpr UINT kMemoryMenuCopyHistoryRow = 51510;
constexpr UINT kMemoryMenuCopyHistoryVisible = 51511;
constexpr UINT kMemoryMenuShowEditableHex = 51512;
constexpr UINT kMemoryMenuShowHexAscii = 51513;
constexpr UINT kMemoryMenuShowTextRuns = 51514;
constexpr UINT kMemoryMenuExportSnapshotText = 51515;
constexpr UINT kMemoryMenuExportSnapshotBinary = 51516;
constexpr UINT kMemoryMenuPreviewDiff = 51517;
constexpr UINT kMemoryMenuApplyDiff = 51518;
constexpr UINT kMsgMemoryOperationCompleted = WM_APP + 598;
constexpr UINT kMsgMemoryHistoryFilterCompleted = WM_APP + 599;
constexpr UINT kMsgMemorySelectProcess = WM_APP + 600;

enum class SnapshotPresentation {
    kEditableHex,
    kHexAscii,
    kTextRuns,
};

struct MemoryOperationSnapshot {
    bool readOperation = false;
    bool stagedWritebackOperation = false;
    bool forceWriteback = false;
    std::size_t writebackFirstPendingBlock = 0;
    DWORD processId = 0;
    std::uint64_t address = 0;
    std::size_t requestedBytes = 0;
    DriverMemoryReadResult readResult;
    DriverMemoryWriteResult writeResult;
    MemoryWritePlan writebackPlan;
    DriverMemoryWritebackResult writebackResult;
};

struct MemoryHistoryEntry {
    std::uint64_t sequence = 0;
    std::wstring operation;
    DWORD processId = 0;
    std::uint64_t address = 0;
    std::size_t requestedBytes = 0;
    std::size_t completedBytes = 0;
    bool success = false;
    std::wstring status;
};

struct MemoryHistoryFilterResult {
    std::uint64_t generation = 0;
    std::wstring query;
    bool useRegex = false;
    std::vector<std::size_t> visibleIndexes;
};

// MemoryViewLifetime survives a nested modal message loop long enough for the
// caller to prove the page still owns its state after MessageBoxW returns.
struct MemoryViewLifetime final {
    std::atomic_bool alive = true;
};

// DriverMemoryViewState owns child HWNDs and the driver facade for one page.
// Inputs arrive through window messages; processing validates edit-control text
// and calls DriverMemoryClient; return values are produced by WndProc message
// handling rather than by this state object.
struct DriverMemoryViewState {
    HWND hwnd = nullptr;
    HWND pidEdit = nullptr;
    HWND addressEdit = nullptr;
    HWND lengthEdit = nullptr;
    HWND hexEdit = nullptr;
    HWND statusEdit = nullptr;
    HWND readButton = nullptr;
    HWND writeButton = nullptr;
    HWND previewDiffButton = nullptr;
    HWND applyDiffButton = nullptr;
    HWND snapshotPreviousButton = nullptr;
    HWND snapshotNextButton = nullptr;
    HWND historyFilter = nullptr;
    bool operationInProgress = false;
    std::vector<MemoryHistoryEntry> history;
    std::uint64_t nextHistorySequence = 1;
    MemorySnapshotHistory snapshots;
    MemoryWritePlan preparedWritePlan;
    bool hasPreparedWritePlan = false;
    std::shared_ptr<MemoryViewLifetime> lifetime = std::make_shared<MemoryViewLifetime>();
    std::shared_ptr<DriverMemoryWritebackCancellation> writebackCancellation;
    SnapshotPresentation snapshotPresentation = SnapshotPresentation::kEditableHex;
    std::wstring editableHexText;
    bool hasEditableHexText = false;
    std::uint64_t historyGeneration = 0;
    std::wstring historyFilterQuery;
    bool historyFilterUseRegex = false;
    int historyContextColumn = 0;
    ksword::ui::VirtualListView historyList;
    std::shared_ptr<const std::vector<ksword::ui::VirtualListRow>> historyFilterRows;
    std::unique_ptr<ksword::ui::AsyncSnapshotTask<MemoryOperationSnapshot>> operationTask;
    std::unique_ptr<ksword::ui::AsyncSnapshotTask<MemoryHistoryFilterResult>> historyFilterTask;
};

DriverMemoryViewState* stateFromWindow(HWND hwnd);
std::wstring formatHex64(std::uint64_t value);

// getWindowTextString copies text from a Win32 edit control. Input is the child
// HWND; processing queries length and copies the text; output is an empty string
// for null handles or controls without text.
std::wstring getWindowTextString(HWND hwnd) {
    if (!hwnd) {
        return std::wstring();
    }
    const int kLength = ::GetWindowTextLengthW(hwnd);
    if (kLength <= 0) {
        return std::wstring();
    }
    std::wstring text(static_cast<std::size_t>(kLength) + 1, L'\0');
    ::GetWindowTextW(hwnd, &text[0], kLength + 1);
    text.resize(static_cast<std::size_t>(kLength));
    return text;
}

// setStatus writes a human-readable status message. Inputs are page state and
// text; processing updates the multiline status edit; no value is returned.
void setStatus(DriverMemoryViewState& state, const std::wstring& text) {
    if (state.statusEdit) {
        ::SetWindowTextW(state.statusEdit, text.c_str());
    }
}

// invalidatePreparedWritePlan makes any text, target, or snapshot transition
// require a fresh local diff calculation before it can reach the driver.
void invalidatePreparedWritePlan(DriverMemoryViewState& state) {
    state.preparedWritePlan = {};
    state.hasPreparedWritePlan = false;
}

// updateSnapshotButtons makes snapshot navigation opt-in and prevents a stale
// button click while an I/O request is running. A snapshot is local immutable
// data, so moving through it never triggers a driver request.
void updateSnapshotButtons(DriverMemoryViewState& state) {
    const bool kEnabled = !state.operationInProgress;
    const bool kEditable = state.snapshotPresentation == SnapshotPresentation::kEditableHex;
    const bool kCanStageWriteback = kEnabled && kEditable && state.snapshots.current() != nullptr;
    if (state.snapshotPreviousButton) {
        ::EnableWindow(state.snapshotPreviousButton, kEnabled && state.snapshots.canMovePrevious());
    }
    if (state.snapshotNextButton) {
        ::EnableWindow(state.snapshotNextButton, kEnabled && state.snapshots.canMoveNext());
    }
    if (state.writeButton) {
        ::EnableWindow(state.writeButton, kEnabled && kEditable);
    }
    if (state.previewDiffButton) {
        ::EnableWindow(state.previewDiffButton, kCanStageWriteback);
    }
    if (state.applyDiffButton) {
        ::EnableWindow(state.applyDiffButton, kCanStageWriteback && state.hasPreparedWritePlan);
    }
    ::InvalidateRect(state.hwnd, nullptr, FALSE);
}

// applyCurrentSnapshot replaces the editable fields with one already-read
// snapshot. The action intentionally preserves the original returned length so
// a partial driver read cannot be presented as a complete requested range.
bool applyCurrentSnapshot(DriverMemoryViewState& state) {
    const MemoryReadSnapshot* snapshot = state.snapshots.current();
    if (!snapshot) {
        return false;
    }
    invalidatePreparedWritePlan(state);
    if (state.pidEdit) {
        ::SetWindowTextW(state.pidEdit, std::to_wstring(snapshot->processId).c_str());
    }
    if (state.addressEdit) {
        ::SetWindowTextW(state.addressEdit, formatHex64(snapshot->address).c_str());
    }
    if (state.lengthEdit) {
        ::SetWindowTextW(state.lengthEdit, std::to_wstring(snapshot->bytes.size()).c_str());
    }
    state.snapshotPresentation = SnapshotPresentation::kEditableHex;
    state.editableHexText = formatHexBytesForDisplay(snapshot->bytes);
    state.hasEditableHexText = true;
    if (state.hexEdit) {
        ::SendMessageW(state.hexEdit, EM_SETREADONLY, FALSE, 0);
        ::SetWindowTextW(state.hexEdit, state.editableHexText.c_str());
    }
    std::wstring status = snapshot->statusText;
    if (!status.empty()) {
        status += L"\r\n";
    }
    status += L"已打开内存快照 " + std::to_wstring(state.snapshots.currentPosition()) + L"/" +
        std::to_wstring(state.snapshots.size()) + L"；未重新读取目标进程。";
    setStatus(state, status);
    updateSnapshotButtons(state);
    return true;
}

std::wstring formatHex64(const std::uint64_t value) {
    std::wostringstream stream;
    stream << L"0x" << std::hex << std::uppercase << value;
    return stream.str();
}

std::vector<ksword::ui::ListViewColumn> memoryHistoryColumns() {
    return {
        { 0, 68, LVCFMT_RIGHT, L"序号" },
        { 1, 74, LVCFMT_LEFT, L"操作" },
        { 2, 74, LVCFMT_RIGHT, L"PID" },
        { 3, 150, LVCFMT_LEFT, L"地址" },
        { 4, 88, LVCFMT_RIGHT, L"请求字节" },
        { 5, 88, LVCFMT_RIGHT, L"完成字节" },
        { 6, 70, LVCFMT_LEFT, L"结果" },
        { 7, 520, LVCFMT_LEFT, L"状态" },
    };
}

void applyMemoryHistoryFilter(DriverMemoryViewState& state, MemoryHistoryFilterResult result) {
    if (result.generation != state.historyGeneration || result.query != state.historyFilterQuery ||
        result.useRegex != state.historyFilterUseRegex) {
        return;
    }
    state.historyList.setVisibleIndexes(std::move(result.visibleIndexes));
}

void requestMemoryHistoryFilter(DriverMemoryViewState& state, std::wstring query) {
    state.historyFilterQuery = std::move(query);
    state.historyFilterUseRegex = ksword::ui::getFilterBarRegexEnabled(state.historyFilter);
    const auto kRows = state.historyFilterRows;
    const std::uint64_t kGeneration = state.historyGeneration;
    const bool kUseRegex = state.historyFilterUseRegex;
    if (!state.historyFilterTask || !kRows) {
        return;
    }
    state.historyFilterTask->request(
        [kRows, kGeneration, kUseRegex, query = state.historyFilterQuery]() mutable {
            MemoryHistoryFilterResult result{};
            result.generation = kGeneration;
            result.query = std::move(query);
            result.useRegex = kUseRegex;
            result.visibleIndexes = ksword::ui::VirtualListView::filterRowIndexes(*kRows, result.query, kUseRegex);
            return result;
        },
        [&state](std::uint64_t, std::optional<MemoryHistoryFilterResult>&& result, std::exception_ptr error) {
            if (error || !result.has_value()) {
                setStatus(state, L"内存操作历史筛选异常结束，已保留当前可见结果。");
                return;
            }
            applyMemoryHistoryFilter(state, std::move(*result));
        });
}

void rebuildMemoryHistory(DriverMemoryViewState& state) {
    auto rows = std::make_shared<std::vector<ksword::ui::VirtualListRow>>();
    rows->reserve(state.history.size());
    for (const MemoryHistoryEntry& entry : state.history) {
        ksword::ui::VirtualListRow row{};
        row.stableKey = std::to_wstring(entry.sequence);
        row.cells = {
            std::to_wstring(entry.sequence),
            entry.operation,
            std::to_wstring(entry.processId),
            formatHex64(entry.address),
            std::to_wstring(entry.requestedBytes),
            std::to_wstring(entry.completedBytes),
            entry.success ? L"成功" : L"失败",
            entry.status,
        };
        // The state text is both visible and part of the immutable filtering
        // snapshot, so local filtering never performs another driver query.
        row.stableKey += L"|" + entry.status;
        rows->push_back(std::move(row));
    }
    state.historyList.setRows(*rows);
    state.historyFilterRows = std::move(rows);
    ++state.historyGeneration;
    requestMemoryHistoryFilter(state, state.historyFilter ? ksword::ui::getFilterBarText(state.historyFilter) : state.historyFilterQuery);
}

void appendMemoryHistory(DriverMemoryViewState& state, const MemoryOperationSnapshot& snapshot) {
    MemoryHistoryEntry entry{};
    entry.sequence = state.nextHistorySequence++;
    entry.operation = snapshot.readOperation ? L"读取" :
        (snapshot.stagedWritebackOperation ? (snapshot.forceWriteback ? L"差异写回 (FORCE)" : L"差异写回") : L"写入");
    entry.processId = snapshot.processId;
    entry.address = snapshot.address;
    entry.requestedBytes = snapshot.requestedBytes;
    if (snapshot.readOperation) {
        entry.success = snapshot.readResult.success;
        entry.completedBytes = snapshot.readResult.bytes.size();
        entry.status = snapshot.readResult.statusText;
    } else if (snapshot.stagedWritebackOperation) {
        entry.success = snapshot.writebackResult.success;
        entry.completedBytes = snapshot.writebackResult.bytesWritten;
        entry.status = snapshot.writebackResult.statusText;
    } else {
        entry.success = snapshot.writeResult.success;
        entry.completedBytes = snapshot.writeResult.bytesWritten;
        entry.status = snapshot.writeResult.statusText;
    }
    if (entry.status.empty()) {
        entry.status = entry.success ? L"操作完成。" : L"操作失败。";
    }
    constexpr std::size_t kMaxHistoryEntries = 512;
    state.history.push_back(std::move(entry));
    if (state.history.size() > kMaxHistoryEntries) {
        state.history.erase(state.history.begin(), state.history.begin() + static_cast<std::ptrdiff_t>(state.history.size() - kMaxHistoryEntries));
    }
    rebuildMemoryHistory(state);
}

// copyTextToClipboard delegates to the shared export utility so memory-page
// copies are captured by the evidence session like every other Lite export.
bool copyTextToClipboard(HWND owner, const std::wstring& text) {
    return ksword::ui::copyTextToClipboard(owner, text, L"内存快照");
}

// textFromClipboard reads CF_UNICODETEXT for paste into the hex buffer. Input is
// an owner HWND; processing copies the global clipboard text before unlocking;
// output is empty when the clipboard does not contain Unicode text.
std::wstring textFromClipboard(HWND owner) {
    if (!::OpenClipboard(owner)) {
        return {};
    }
    HANDLE data = ::GetClipboardData(CF_UNICODETEXT);
    if (!data) {
        ::CloseClipboard();
        return {};
    }
    const wchar_t* text = static_cast<const wchar_t*>(::GlobalLock(data));
    std::wstring output = text ? std::wstring(text) : std::wstring();
    if (text) {
        ::GlobalUnlock(data);
    }
    ::CloseClipboard();
    return output;
}

// replaceEditSelection inserts text into an edit control. Inputs are edit HWND
// and text; processing uses EM_REPLACESEL so paste respects the current
// selection/caret; no value is returned.
void replaceEditSelection(HWND edit, const std::wstring& text) {
    if (edit) {
        ::SendMessageW(edit, EM_REPLACESEL, TRUE, reinterpret_cast<LPARAM>(text.c_str()));
    }
}

// selectAllEditText selects all text in a target edit control. Input is edit
// HWND; processing sends EM_SETSEL; no value is returned.
void selectAllEditText(HWND edit) {
    if (edit) {
        ::SendMessageW(edit, EM_SETSEL, 0, -1);
        ::SetFocus(edit);
    }
}

// createEdit creates a single-line or multiline edit control with the project
// UI font. Inputs are parent/id/geometry/style flags; processing calls
// CreateWindowExW; output is the child HWND.
HWND createEdit(HWND parent, int id, const wchar_t* text, int x, int y, int w, int h, DWORD extraStyle) {
    HWND hwnd = ::CreateWindowExW(WS_EX_CLIENTEDGE,
        L"EDIT",
        text ? text : L"",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL | extraStyle,
        x,
        y,
        w,
        h,
        parent,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)),
        ::GetModuleHandleW(nullptr),
        nullptr);
    if (hwnd) {
        ::SendMessageW(hwnd, WM_SETFONT, reinterpret_cast<WPARAM>(ksword::ui::systemUiFont()), TRUE);
    }
    return hwnd;
}

// layoutChildren positions all controls inside the page. Input is the page
// state and current client rectangle; processing computes a simple two-panel
// layout; no value is returned.
void layoutChildren(DriverMemoryViewState& state, const RECT& rc) {
    const int kMargin = 12;
    const int kLabelWidth = 58;
    const int kEditHeight = 24;
    const int kButtonWidth = 88;
    const int kSnapshotButtonWidth = 74;
    const int kGap = 8;
    const int kWidth = rc.right - rc.left;
    const int kHeight = rc.bottom - rc.top;
    const int kRowTop = kMargin + 26;
    const int kInputWidth = 130;

    ::MoveWindow(state.pidEdit, kMargin + kLabelWidth, kRowTop, kInputWidth, kEditHeight, TRUE);
    ::MoveWindow(state.addressEdit, kMargin + kLabelWidth + kInputWidth + 72, kRowTop, kInputWidth + 70, kEditHeight, TRUE);
    ::MoveWindow(state.lengthEdit, kMargin + kLabelWidth + kInputWidth + 72 + kInputWidth + 70 + 72, kRowTop, kInputWidth, kEditHeight, TRUE);

    const int kButtonTop = kRowTop + kEditHeight + kGap;
    ::MoveWindow(state.readButton, kMargin, kButtonTop, kButtonWidth, kEditHeight + 2, TRUE);
    ::MoveWindow(state.writeButton, kMargin + kButtonWidth + kGap, kButtonTop, kButtonWidth, kEditHeight + 2, TRUE);
    ::MoveWindow(state.previewDiffButton, kMargin + (kButtonWidth + kGap) * 2, kButtonTop, kButtonWidth, kEditHeight + 2, TRUE);
    ::MoveWindow(state.applyDiffButton, kMargin + (kButtonWidth + kGap) * 3, kButtonTop, kButtonWidth, kEditHeight + 2, TRUE);
    ::MoveWindow(state.snapshotPreviousButton, kMargin + (kButtonWidth + kGap) * 4, kButtonTop, kSnapshotButtonWidth, kEditHeight + 2, TRUE);
    ::MoveWindow(state.snapshotNextButton, kMargin + (kButtonWidth + kGap) * 4 + kSnapshotButtonWidth + kGap, kButtonTop, kSnapshotButtonWidth, kEditHeight + 2, TRUE);

    const int kFilterTop = kButtonTop + kEditHeight + kGap;
    const int kHexTop = kFilterTop + kEditHeight + kGap;
    const int kStatusHeight = 42;
    const int kHistoryHeight = 112;
    const int kHexHeight = std::max(64, kHeight - kHexTop - kStatusHeight - kHistoryHeight - (kMargin * 2) - (kGap * 3));
    const int kContentWidth = std::max(100, kWidth - kMargin * 2);
    ::MoveWindow(state.historyFilter, kMargin, kFilterTop, kContentWidth, kEditHeight, TRUE);
    ::MoveWindow(state.hexEdit, kMargin, kHexTop, kContentWidth, kHexHeight, TRUE);
    ::MoveWindow(state.statusEdit, kMargin, kHexTop + kHexHeight + kGap, kContentWidth, kStatusHeight, TRUE);
    const int kHistoryTop = kHexTop + kHexHeight + kGap + kStatusHeight + kGap;
    ::MoveWindow(state.historyList.hwnd(), kMargin, kHistoryTop, kContentWidth, kHistoryHeight, TRUE);
}

// paintLabels draws static labels directly on the page to keep the child window
// count small. Input is page HWND and paint DC; processing draws title and field
// labels using the shared theme; no value is returned.
void paintLabels(HWND hwnd, HDC dc) {
    RECT rc{};
    ::GetClientRect(hwnd, &rc);
    ::FillRect(dc, &rc, ksword::ui::appTheme().windowBrush());

    const COLORREF kText = ksword::ui::appTheme().textColor;
    const COLORREF kMuted = ksword::ui::appTheme().mutedTextColor;
    RECT title{ 12, 8, rc.right - 12, 28 };
    ksword::ui::drawTextLine(dc, L"Driver Memory Read / Write / Verify", title, kText, ksword::ui::systemUiFont(), DT_LEFT | DT_VCENTER | DT_SINGLELINE);

    RECT pid{ 12, 38, 70, 62 };
    RECT address{ 200, 38, 272, 62 };
    RECT length{ 472, 38, 544, 62 };
    RECT filter{ 12, 96, rc.right - 12, 118 };
    ksword::ui::drawTextLine(dc, L"PID", pid, kMuted, ksword::ui::systemUiFont(), DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    ksword::ui::drawTextLine(dc, L"Address", address, kMuted, ksword::ui::systemUiFont(), DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    ksword::ui::drawTextLine(dc, L"Length", length, kMuted, ksword::ui::systemUiFont(), DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    ksword::ui::drawTextLine(dc, L"操作历史筛选（匹配全部列和状态）", filter, kMuted, ksword::ui::systemUiFont(), DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    const DriverMemoryViewState* state = stateFromWindow(hwnd);
    const std::wstring kSnapshotText = state && state->snapshots.current()
        ? L"读取快照 " + std::to_wstring(state->snapshots.currentPosition()) + L"/" + std::to_wstring(state->snapshots.size()) + L"（右键检视/导出；差异写回已冻结目标）"
        : L"读取快照 0/0";
    RECT snapshot{ 372, 70, rc.right - 12, 94 };
    ksword::ui::drawTextLine(dc, kSnapshotText, snapshot, kMuted, ksword::ui::systemUiFont(), DT_LEFT | DT_VCENTER | DT_SINGLELINE);
}

// stateFromWindow returns the state pointer stored on the page HWND. Input is a
// page HWND; processing reads GWLP_USERDATA; output is null before WM_NCCREATE
// finishes or after WM_NCDESTROY clears the pointer.
DriverMemoryViewState* stateFromWindow(HWND hwnd) {
    return reinterpret_cast<DriverMemoryViewState*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
}

// currentLiveState rejects a stale reference after a modal dialog has pumped
// WM_NCDESTROY. The token is captured before the dialog and is cleared before
// the owning state is released, so a recycled HWND cannot be mistaken for it.
DriverMemoryViewState* currentLiveState(HWND hwnd, const std::shared_ptr<MemoryViewLifetime>& lifetime) {
    if (!lifetime || !lifetime->alive.load(std::memory_order_acquire)) {
        return nullptr;
    }
    DriverMemoryViewState* state = stateFromWindow(hwnd);
    if (!state || state->lifetime.get() != lifetime.get()) {
        return nullptr;
    }
    return state;
}

// selectProcessForMemoryOperations prepares only local input controls for a
// process-navigation request. It never sends a driver request: the address is
// deliberately reset and the old editable bytes are cleared so a user must
// choose a range and explicitly start a new read before any write is possible.
bool selectProcessForMemoryOperations(DriverMemoryViewState& state, const DWORD processId) {
    if (processId == 0U) {
        setStatus(state, L"内存操作目标 PID 必须非零。");
        return false;
    }
    if (state.operationInProgress) {
        setStatus(state, L"内存操作正在执行，完成后再切换目标进程。");
        return false;
    }

    invalidatePreparedWritePlan(state);
    state.snapshotPresentation = SnapshotPresentation::kEditableHex;
    state.editableHexText.clear();
    state.hasEditableHexText = false;
    if (state.pidEdit) {
        ::SetWindowTextW(state.pidEdit, std::to_wstring(processId).c_str());
    }
    if (state.addressEdit) {
        ::SetWindowTextW(state.addressEdit, L"0x0");
    }
    if (state.lengthEdit) {
        ::SetWindowTextW(state.lengthEdit, L"16");
    }
    if (state.hexEdit) {
        ::SendMessageW(state.hexEdit, EM_SETREADONLY, FALSE, 0);
        ::SetWindowTextW(state.hexEdit, L"");
    }
    updateSnapshotButtons(state);
    setStatus(state, L"已选择 PID " + std::to_wstring(processId) +
        L" 作为下一次内存读取目标；已清空旧编辑缓冲，尚未发送读取或写入请求。请输入地址后显式读取。");
    if (state.addressEdit) {
        ::SetFocus(state.addressEdit);
        ::SendMessageW(state.addressEdit, EM_SETSEL, 0, -1);
    }
    return true;
}

// handleRead validates read fields and invokes the driver facade. Input is page
// state; processing parses PID/address/length and calls DriverMemoryClient;
// output is reflected in the hex and status edit controls.
void handleRead(DriverMemoryViewState& state) {
    DriverMemoryReadRequest request;
    std::wstring error;
    if (!parseReadRequest(getWindowTextString(state.pidEdit),
            getWindowTextString(state.addressEdit),
            getWindowTextString(state.lengthEdit),
            request,
            error)) {
        setStatus(state, error);
        return;
    }

    if (state.operationInProgress || !state.operationTask) {
        setStatus(state, L"内存操作正在执行。");
        return;
    }
    state.operationInProgress = true;
    ::EnableWindow(state.readButton, FALSE);
    ::EnableWindow(state.writeButton, FALSE);
    updateSnapshotButtons(state);
    setStatus(state, L"正在后台执行 R0 内存读取…");
    state.operationTask->request(
        [request] {
            MemoryOperationSnapshot snapshot{};
            snapshot.readOperation = true;
            snapshot.processId = request.processId;
            snapshot.address = request.address;
            snapshot.requestedBytes = request.length;
            DriverMemoryClient client;
            snapshot.readResult = client.readMemory(request);
            return snapshot;
        },
        [&state](std::uint64_t, std::optional<MemoryOperationSnapshot>&& snapshot, std::exception_ptr error) {
            state.operationInProgress = false;
            ::EnableWindow(state.readButton, TRUE);
            ::EnableWindow(state.writeButton, TRUE);
            if (error || !snapshot.has_value()) {
                setStatus(state, L"R0 内存读取异常结束。");
                updateSnapshotButtons(state);
                return;
            }
            if (snapshot->readResult.success && state.snapshots.record(snapshot->processId,
                    snapshot->address,
                    snapshot->requestedBytes,
                    snapshot->readResult.bytes,
                    snapshot->readResult.statusText)) {
                applyCurrentSnapshot(state);
            } else {
                setStatus(state, snapshot->readResult.statusText);
            }
            appendMemoryHistory(state, *snapshot);
            updateSnapshotButtons(state);
        });
}

// handleWrite validates write fields and invokes the driver facade. Input is
// page state; processing parses PID/address/hex bytes and calls
// DriverMemoryClient; output is reflected in the status edit control.
void handleWrite(DriverMemoryViewState& state) {
    if (state.snapshotPresentation != SnapshotPresentation::kEditableHex) {
        setStatus(state, L"当前显示的是只读快照检视；请先切回可编辑 Hex。");
        return;
    }
    DriverMemoryWriteRequest request;
    std::wstring error;
    if (!parseWriteRequest(getWindowTextString(state.pidEdit),
            getWindowTextString(state.addressEdit),
            getWindowTextString(state.hexEdit),
            request,
            error)) {
        setStatus(state, error);
        return;
    }

    if (state.operationInProgress || !state.operationTask) {
        setStatus(state, L"内存操作正在执行。");
        return;
    }
    state.operationInProgress = true;
    ::EnableWindow(state.readButton, FALSE);
    ::EnableWindow(state.writeButton, FALSE);
    updateSnapshotButtons(state);
    setStatus(state, L"正在后台执行 R0 内存写入…");
    state.operationTask->request(
        [request = std::move(request)] {
            MemoryOperationSnapshot snapshot{};
            snapshot.processId = request.processId;
            snapshot.address = request.address;
            snapshot.requestedBytes = request.bytes.size();
            DriverMemoryClient client;
            snapshot.writeResult = client.writeMemory(request);
            return snapshot;
        },
        [&state](std::uint64_t, std::optional<MemoryOperationSnapshot>&& snapshot, std::exception_ptr error) {
            state.operationInProgress = false;
            ::EnableWindow(state.readButton, TRUE);
            ::EnableWindow(state.writeButton, TRUE);
            if (error || !snapshot.has_value()) {
                invalidatePreparedWritePlan(state);
                setStatus(state, L"R0 内存写入异常结束。");
                updateSnapshotButtons(state);
                return;
            }
            invalidatePreparedWritePlan(state);
            setStatus(state, snapshot->writeResult.statusText);
            appendMemoryHistory(state, *snapshot);
            updateSnapshotButtons(state);
        });
}

// prepareWritePlan turns only the local editable buffer into a frozen plan for
// the current immutable read snapshot. PID/address edits are deliberately not
// inputs here: writeback always targets the snapshot identity that supplied the
// original bytes.
void prepareWritePlan(DriverMemoryViewState& state) {
    if (state.operationInProgress || state.snapshotPresentation != SnapshotPresentation::kEditableHex) {
        setStatus(state, L"请先结束当前操作并切回可编辑 Hex，再预览差异。");
        return;
    }
    const MemoryReadSnapshot* snapshot = state.snapshots.current();
    if (!snapshot) {
        setStatus(state, L"请先成功读取内存；差异写回只能基于不可变读取快照。");
        return;
    }

    std::vector<std::uint8_t> editedBytes;
    std::wstring error;
    if (!parseHexBytes(getWindowTextString(state.hexEdit), editedBytes, error)) {
        invalidatePreparedWritePlan(state);
        setStatus(state, error);
        updateSnapshotButtons(state);
        return;
    }

    MemoryWritePlan plan{};
    if (!buildMemoryWritePlan(*snapshot, editedBytes, kMemoryWritePlanBlockBytes, plan, error)) {
        invalidatePreparedWritePlan(state);
        setStatus(state, L"无法预览差异：" + error);
        updateSnapshotButtons(state);
        return;
    }
    state.preparedWritePlan = std::move(plan);
    state.hasPreparedWritePlan = !state.preparedWritePlan.blocks.empty();
    if (!state.hasPreparedWritePlan) {
        setStatus(state, L"没有检测到差异；未发送写入请求。");
    } else {
        setStatus(state, L"差异预览完成：" + std::to_wstring(state.preparedWritePlan.blocks.size()) + L" 个连续块、" +
            std::to_wstring(state.preparedWritePlan.changedByteCount) + L" 字节。写回目标已冻结为快照 PID=" +
            std::to_wstring(state.preparedWritePlan.processId) + L"，地址=" + formatHex64(state.preparedWritePlan.baseAddress) + L"。");
    }
    updateSnapshotButtons(state);
}

bool preparedPlanMatchesEditableBuffer(const DriverMemoryViewState& state, std::wstring& errorText) {
    errorText.clear();
    if (!state.hasPreparedWritePlan || state.snapshotPresentation != SnapshotPresentation::kEditableHex) {
        errorText = L"请先在可编辑 Hex 视图中预览差异。";
        return false;
    }
    const MemoryReadSnapshot* snapshot = state.snapshots.current();
    if (!snapshot || snapshot->sequence != state.preparedWritePlan.snapshotSequence ||
        snapshot->processId != state.preparedWritePlan.processId || snapshot->address != state.preparedWritePlan.baseAddress) {
        errorText = L"读取快照已变化，请重新预览差异。";
        return false;
    }
    std::vector<std::uint8_t> editedBytes;
    if (!parseHexBytes(getWindowTextString(state.hexEdit), editedBytes, errorText)) {
        return false;
    }
    if (editedBytes != state.preparedWritePlan.desiredSnapshotBytes) {
        errorText = L"Hex 缓冲在预览后已变化，请重新预览差异。";
        return false;
    }
    return true;
}

bool confirmWritebackPlan(HWND owner, const MemoryWritePlan& plan) {
    const std::wstring kPrompt = L"将对已读取的内存快照写入 " + std::to_wstring(plan.blocks.size()) + L" 个差异块（" +
        std::to_wstring(plan.changedByteCount) + L" 字节）。\r\n\r\nPID=" + std::to_wstring(plan.processId) +
        L"\r\n地址=" + formatHex64(plan.baseAddress) +
        L"\r\n\r\n每一块都会先精确复读原始字节，写入后再精确验证；不使用 FORCE。\r\n"
        L"目标进程仍可能并发变化，操作不可回滚。是否开始？";
    return ::MessageBoxW(owner, kPrompt.c_str(), L"应用内存差异", MB_ICONWARNING | MB_YESNO | MB_DEFBUTTON2) == IDYES;
}

std::size_t pendingWritePlanBytes(const MemoryWritePlan& plan, const std::size_t firstPendingBlock) {
    if (firstPendingBlock > plan.blocks.size()) {
        return 0U;
    }
    std::size_t bytes = 0U;
    for (std::size_t index = firstPendingBlock; index < plan.blocks.size(); ++index) {
        bytes += plan.blocks[index].desiredAfter.size();
    }
    return bytes;
}

bool confirmForceWritebackPlan(HWND owner,
    const MemoryWritePlan& plan,
    const std::size_t firstPendingBlock,
    const std::size_t verifiedPrefixBlocks,
    const std::size_t verifiedPrefixBytes) {
    if (firstPendingBlock >= plan.blocks.size()) {
        return false;
    }
    const std::size_t kPendingBlocks = plan.blocks.size() - firstPendingBlock;
    const std::size_t kPendingBytes = pendingWritePlanBytes(plan, firstPendingBlock);
    const std::wstring kPrefix = firstPendingBlock == 0U
        ? L"本次普通尝试未报告写入任何差异字节。"
        : L"普通路径已写入并逐块验证前 " + std::to_wstring(verifiedPrefixBlocks) + L" 个差异块（" +
            std::to_wstring(verifiedPrefixBytes) + L" 字节）；当前拒绝块报告 0 字节写入。";
    const std::wstring kPrompt = L"驱动拒绝了普通差异写回并要求 FORCE。\r\n" + kPrefix + L"\r\n\r\nPID=" +
        std::to_wstring(plan.processId) + L"\r\n地址=" + formatHex64(plan.baseAddress) + L"\r\n剩余差异块=" +
        std::to_wstring(kPendingBlocks) + L"，字节=" + std::to_wstring(kPendingBytes) +
        L"\r\n\r\n若继续，只会对上述剩余块重新逐块复读原始字节后以 FORCE 写入，并逐块复读验证；"
        L"已验证的普通写入块不会被重写。FORCE 可能导致目标进程崩溃、数据损坏或系统不稳定。是否明确继续？";
    return ::MessageBoxW(owner, kPrompt.c_str(), L"确认 FORCE 内存差异写回", MB_ICONWARNING | MB_YESNO | MB_DEFBUTTON2) == IDYES;
}

void beginApplyWritePlan(DriverMemoryViewState& state, bool forceWrite, std::size_t firstPendingBlock);

// completeWriteback applies the result only after a complete full-range read
// matches the desired bytes. The only retained retry path is a separately
// confirmed FORCE continuation whose preceding normal-write blocks were already
// verified and whose current rejected block reported zero bytes written.
void completeWriteback(DriverMemoryViewState& state,
    const MemoryOperationSnapshot& snapshot,
    const std::exception_ptr error) {
    state.writebackCancellation.reset();
    state.operationInProgress = false;
    ::EnableWindow(state.readButton, TRUE);
    ::EnableWindow(state.writeButton, TRUE);
    if (error) {
        invalidatePreparedWritePlan(state);
        setStatus(state, L"差异写回异常结束；当前编辑未作为新快照保存，请重新读取目标进程。");
        updateSnapshotButtons(state);
        return;
    }

    appendMemoryHistory(state, snapshot);
    const DriverMemoryWritebackResult& result = snapshot.writebackResult;
    if (result.success) {
        if (state.snapshots.record(snapshot.writebackPlan.processId,
                snapshot.writebackPlan.baseAddress,
                snapshot.writebackPlan.desiredSnapshotBytes.size(),
                result.finalReadResult.bytes,
                result.statusText)) {
            applyCurrentSnapshot(state);
            return;
        }
        invalidatePreparedWritePlan(state);
        setStatus(state, L"差异块已验证，但无法保存完整复读快照；请重新读取目标进程。");
        updateSnapshotButtons(state);
        return;
    }

    const bool kCanContinueWithForce = result.forceRequired && !snapshot.forceWriteback &&
        result.forceRequiredBlockIndex < snapshot.writebackPlan.blocks.size() &&
        result.forceRequiredBlockIndex >= snapshot.writebackFirstPendingBlock &&
        result.verifiedBlocks == result.forceRequiredBlockIndex - snapshot.writebackFirstPendingBlock;
    if (kCanContinueWithForce) {
        const HWND kOwner = state.hwnd;
        const std::shared_ptr<MemoryViewLifetime> kLifetime = state.lifetime;
        const MemoryWritePlan kPlan = snapshot.writebackPlan;
        const std::size_t kFirstPendingBlock = result.forceRequiredBlockIndex;
        const bool kAccepted = confirmForceWritebackPlan(kOwner,
            kPlan,
            kFirstPendingBlock,
            result.forceRequiredBlockIndex,
            result.bytesWritten);
        DriverMemoryViewState* liveState = currentLiveState(kOwner, kLifetime);
        if (!liveState) {
            return;
        }
        if (kAccepted) {
            beginApplyWritePlan(*liveState, true, kFirstPendingBlock);
            return;
        }
        setStatus(*liveState, result.statusText + L"\r\n已取消 FORCE 写回；当前编辑仍保留，未更新快照基线。");
        updateSnapshotButtons(*liveState);
        return;
    }

    invalidatePreparedWritePlan(state);
    setStatus(state, result.statusText + L"\r\n当前编辑仍保留，但已失效；请重新读取并预览差异后再试。");
    updateSnapshotButtons(state);
}

// beginApplyWritePlan executes a previously confirmed plan asynchronously. The
// worker owns a copy of the immutable plan and cancellation token and never
// touches HWND state.
void beginApplyWritePlan(DriverMemoryViewState& state, const bool forceWrite, const std::size_t firstPendingBlock) {
    if (state.operationInProgress || !state.operationTask || !state.hasPreparedWritePlan) {
        setStatus(state, L"没有可应用的差异计划。");
        return;
    }
    if (firstPendingBlock >= state.preparedWritePlan.blocks.size()) {
        invalidatePreparedWritePlan(state);
        setStatus(state, L"差异写回续写位置无效；请重新读取并预览差异。");
        updateSnapshotButtons(state);
        return;
    }
    std::wstring validationError;
    if (!preparedPlanMatchesEditableBuffer(state, validationError)) {
        invalidatePreparedWritePlan(state);
        setStatus(state, validationError);
        updateSnapshotButtons(state);
        return;
    }

    MemoryWritePlan plan = state.preparedWritePlan;
    const std::shared_ptr<DriverMemoryWritebackCancellation> kCancellation =
        std::make_shared<DriverMemoryWritebackCancellation>();
    state.writebackCancellation = kCancellation;
    state.operationInProgress = true;
    ::EnableWindow(state.readButton, FALSE);
    ::EnableWindow(state.writeButton, FALSE);
    updateSnapshotButtons(state);
    setStatus(state, forceWrite ? L"正在以已确认的 FORCE 后台应用剩余差异并逐块验证…" : L"正在后台应用差异并逐块验证…");
    state.operationTask->request(
        [plan = std::move(plan), forceWrite, firstPendingBlock, kCancellation] () mutable {
            MemoryOperationSnapshot operation{};
            operation.stagedWritebackOperation = true;
            operation.forceWriteback = forceWrite;
            operation.writebackFirstPendingBlock = firstPendingBlock;
            operation.processId = static_cast<DWORD>(plan.processId);
            operation.address = plan.baseAddress;
            operation.requestedBytes = pendingWritePlanBytes(plan, firstPendingBlock);
            operation.writebackPlan = std::move(plan);
            DriverMemoryClient client;
            operation.writebackResult = client.applyWritePlan(
                operation.writebackPlan,
                forceWrite,
                kCancellation.get(),
                firstPendingBlock);
            return operation;
        },
        [&state](std::uint64_t, std::optional<MemoryOperationSnapshot>&& snapshot, std::exception_ptr error) {
            if (!snapshot.has_value()) {
                state.writebackCancellation.reset();
                state.operationInProgress = false;
                ::EnableWindow(state.readButton, TRUE);
                ::EnableWindow(state.writeButton, TRUE);
                invalidatePreparedWritePlan(state);
                setStatus(state, L"差异写回未返回结果；请重新读取目标进程。");
                updateSnapshotButtons(state);
                return;
            }
            completeWriteback(state, *snapshot, error);
        });
}

// handleApplyWritePlan performs the first explicit confirmation. A second,
// separate confirmation is shown only if the driver reports FORCE_REQUIRED.
void handleApplyWritePlan(DriverMemoryViewState& state) {
    std::wstring validationError;
    if (!preparedPlanMatchesEditableBuffer(state, validationError)) {
        invalidatePreparedWritePlan(state);
        setStatus(state, validationError);
        updateSnapshotButtons(state);
        return;
    }

    const HWND kOwner = state.hwnd;
    const std::shared_ptr<MemoryViewLifetime> kLifetime = state.lifetime;
    const MemoryWritePlan kPlan = state.preparedWritePlan;
    const bool kAccepted = confirmWritebackPlan(kOwner, kPlan);
    DriverMemoryViewState* liveState = currentLiveState(kOwner, kLifetime);
    if (!liveState) {
        return;
    }
    if (!kAccepted) {
        setStatus(*liveState, L"已取消应用内存差异。");
        return;
    }
    beginApplyWritePlan(*liveState, false, 0U);
}

void moveToPreviousSnapshot(DriverMemoryViewState& state) {
    if (!state.operationInProgress && state.snapshots.movePrevious()) {
        applyCurrentSnapshot(state);
    }
}

void moveToNextSnapshot(DriverMemoryViewState& state) {
    if (!state.operationInProgress && state.snapshots.moveNext()) {
        applyCurrentSnapshot(state);
    }
}

// normalizeHexBuffer parses and rewrites the hex edit as canonical two-digit
// byte text. Input is page state; processing never performs driver I/O; output
// is reflected in the edit control and status line.
void normalizeHexBuffer(DriverMemoryViewState& state) {
    if (state.snapshotPresentation != SnapshotPresentation::kEditableHex) {
        setStatus(state, L"当前显示的是只读快照检视；请先切回可编辑 Hex。");
        return;
    }
    std::vector<std::uint8_t> bytes;
    std::wstring error;
    if (!parseHexBytes(getWindowTextString(state.hexEdit), bytes, error)) {
        setStatus(state, error);
        return;
    }
    ::SetWindowTextW(state.hexEdit, formatHexBytesForDisplay(bytes).c_str());
    setStatus(state, L"Hex buffer normalized.");
}

// restoreEditableSnapshot returns the byte editor to its local editable buffer.
// The buffer is kept separately from rendered views so merely inspecting ASCII
// or decoded text never mutates the bytes that a later write would parse.
void restoreEditableSnapshot(DriverMemoryViewState& state) {
    const MemoryReadSnapshot* snapshot = state.snapshots.current();
    if (!snapshot) {
        setStatus(state, L"请先成功读取内存，再切换快照检视。");
        return;
    }
    if (!state.hasEditableHexText) {
        state.editableHexText = formatHexBytesForDisplay(snapshot->bytes);
        state.hasEditableHexText = true;
    }
    state.snapshotPresentation = SnapshotPresentation::kEditableHex;
    if (state.hexEdit) {
        ::SendMessageW(state.hexEdit, EM_SETREADONLY, FALSE, 0);
        ::SetWindowTextW(state.hexEdit, state.editableHexText.c_str());
    }
    setStatus(state, L"已切回可编辑 Hex 缓冲；尚未写入目标进程。");
    updateSnapshotButtons(state);
}

// showSnapshotInspection renders an already-read snapshot without re-querying
// the target process. The inspection edit is read-only to prevent its labels or
// decoded text from ever being mistaken for a write payload.
void showSnapshotInspection(DriverMemoryViewState& state, const SnapshotPresentation presentation) {
    const MemoryReadSnapshot* snapshot = state.snapshots.current();
    if (!snapshot) {
        setStatus(state, L"请先成功读取内存，再查看 Hex/ASCII 或文本检视。");
        return;
    }
    if (presentation == SnapshotPresentation::kEditableHex) {
        if (state.snapshotPresentation == SnapshotPresentation::kEditableHex) {
            state.editableHexText = getWindowTextString(state.hexEdit);
            state.hasEditableHexText = true;
            setStatus(state, L"当前已是可编辑 Hex 缓冲；尚未写入目标进程。");
            updateSnapshotButtons(state);
        } else {
            restoreEditableSnapshot(state);
        }
        return;
    }
    if (state.snapshotPresentation == SnapshotPresentation::kEditableHex) {
        state.editableHexText = getWindowTextString(state.hexEdit);
        state.hasEditableHexText = true;
    }
    const std::wstring kRendered = presentation == SnapshotPresentation::kHexAscii
        ? renderMemorySnapshotHexAscii(*snapshot)
        : extractMemorySnapshotText(*snapshot);
    state.snapshotPresentation = presentation;
    if (state.hexEdit) {
        ::SendMessageW(state.hexEdit, EM_SETREADONLY, TRUE, 0);
        ::SetWindowTextW(state.hexEdit, kRendered.c_str());
    }
    setStatus(state, presentation == SnapshotPresentation::kHexAscii
        ? L"正在查看已读快照的 Hex + ASCII；切回“可编辑 Hex”后才可写入。"
        : L"正在查看已读快照中的 ASCII/UTF-16LE 文本；切回“可编辑 Hex”后才可写入。");
    updateSnapshotButtons(state);
}

std::wstring buildSnapshotMetadataText(const MemoryReadSnapshot& snapshot) {
    return L"Snapshot=" + std::to_wstring(snapshot.sequence) + L"; PID=" + std::to_wstring(snapshot.processId) +
        L"; Address=" + formatHex64(snapshot.address) + L"; ReturnedBytes=" + std::to_wstring(snapshot.bytes.size()) +
        L"; Status=" + snapshot.statusText;
}

// exportCurrentSnapshotText persists the local inspection report as UTF-8. It
// has no driver dependency, so a later R0 state change cannot alter this
// evidence artifact.
void exportCurrentSnapshotText(DriverMemoryViewState& state) {
    const MemoryReadSnapshot* snapshot = state.snapshots.current();
    if (!snapshot) {
        setStatus(state, L"没有可导出的内存快照。");
        return;
    }
    const std::wstring kName = L"memory_snapshot_" + std::to_wstring(snapshot->sequence) + L".txt";
    std::wstring error;
    switch (ksword::ui::saveUtf8TextFileWithDialog(state.hwnd,
        kName.c_str(), L"导出内存快照报告", L"Text (*.txt)\0*.txt\0All Files (*.*)\0*.*\0", L"txt",
        buildMemorySnapshotTextReport(*snapshot), &error)) {
    case ksword::ui::SaveTextFileResult::kSaved:
        setStatus(state, L"内存快照报告已导出。");
        break;
    case ksword::ui::SaveTextFileResult::kCancelled:
        setStatus(state, L"已取消导出内存快照报告。");
        break;
    case ksword::ui::SaveTextFileResult::kFailed:
        setStatus(state, L"导出内存快照报告失败：" + error);
        break;
    }
}

// exportCurrentSnapshotBinary writes exactly the bytes returned by the prior
// successful read. Evidence metadata is recorded without copying the arbitrary
// byte payload into the text-only evidence session.
void exportCurrentSnapshotBinary(DriverMemoryViewState& state) {
    const MemoryReadSnapshot* snapshot = state.snapshots.current();
    if (!snapshot) {
        setStatus(state, L"没有可导出的内存快照。");
        return;
    }
    const std::wstring kName = L"memory_snapshot_" + std::to_wstring(snapshot->sequence) + L".bin";
    std::wstring error;
    switch (ksword::ui::saveBinaryFileWithDialog(state.hwnd,
        kName.c_str(), L"导出内存快照二进制", L"Binary (*.bin)\0*.bin\0All Files (*.*)\0*.*\0", L"bin",
        snapshot->bytes, L"内存快照二进制导出", buildSnapshotMetadataText(*snapshot), &error)) {
    case ksword::ui::SaveTextFileResult::kSaved:
        setStatus(state, L"内存快照二进制已导出。");
        break;
    case ksword::ui::SaveTextFileResult::kCancelled:
        setStatus(state, L"已取消导出内存快照二进制。");
        break;
    case ksword::ui::SaveTextFileResult::kFailed:
        setStatus(state, L"导出内存快照二进制失败：" + error);
        break;
    }
}

// showMemoryContextMenu displays compact driver-memory actions. Inputs are page
// state, target child window and screen point; processing groups read/write,
// Hex-buffer, and status commands into submenus before dispatching the selected
// command; no value is returned.
void showMemoryContextMenu(DriverMemoryViewState& state, HWND target, POINT screenPoint) {
    HMENU menu = ::CreatePopupMenu();
    if (!menu) {
        return;
    }
    const bool kTextTarget = target == state.hexEdit || target == state.statusEdit;
    const bool kHexTarget = target == state.hexEdit || target == state.hwnd;
    const bool kCanStartOperation = !state.operationInProgress && state.operationTask != nullptr;
    const bool kCanWritePayload = !state.operationInProgress &&
        state.snapshotPresentation == SnapshotPresentation::kEditableHex;
    const bool kCanEditHex = kHexTarget && !state.operationInProgress &&
        state.snapshotPresentation == SnapshotPresentation::kEditableHex;
    const bool kHasSnapshot = !state.operationInProgress && state.snapshots.current() != nullptr;
    const bool kCanPreviewDiff = kHasSnapshot && state.snapshotPresentation == SnapshotPresentation::kEditableHex;
    const bool kCanApplyDiff = kCanPreviewDiff && state.hasPreparedWritePlan;
    const UINT kSnapshotState = kHasSnapshot ? 0U : MF_GRAYED;
    HMENU driverMenu = ::CreatePopupMenu();
    if (driverMenu) {
        ::AppendMenuW(driverMenu, MF_STRING | (kCanStartOperation ? 0U : MF_GRAYED), kMemoryMenuRead, L"读取");
        ::AppendMenuW(driverMenu, MF_STRING | (kCanStartOperation && kCanWritePayload ? 0U : MF_GRAYED), kMemoryMenuWrite, L"写入");
        ::AppendMenuW(driverMenu, MF_SEPARATOR, 0, nullptr);
        ::AppendMenuW(driverMenu, MF_STRING | (kCanPreviewDiff ? 0U : MF_GRAYED), kMemoryMenuPreviewDiff, L"预览快照差异");
        ::AppendMenuW(driverMenu, MF_STRING | (kCanApplyDiff ? 0U : MF_GRAYED), kMemoryMenuApplyDiff, L"应用已预览差异");
        ::AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(driverMenu), L"驱动内存");
    }
    HMENU hexMenu = ::CreatePopupMenu();
    if (hexMenu) {
        ::AppendMenuW(hexMenu, MF_STRING | (kTextTarget ? 0U : MF_GRAYED), kMemoryMenuSelectAll, L"全选");
        const wchar_t* copyLabel = state.snapshotPresentation == SnapshotPresentation::kEditableHex
            ? L"复制 Hex" : L"复制当前检视";
        ::AppendMenuW(hexMenu, MF_STRING | (kHexTarget ? 0U : MF_GRAYED), kMemoryMenuCopyHex, copyLabel);
        ::AppendMenuW(hexMenu, MF_STRING | (kCanEditHex ? 0U : MF_GRAYED), kMemoryMenuPasteHex, L"粘贴 Hex");
        ::AppendMenuW(hexMenu, MF_STRING | (kCanEditHex ? 0U : MF_GRAYED), kMemoryMenuClearHex, L"清空 Hex");
        ::AppendMenuW(hexMenu, MF_STRING | (kCanEditHex ? 0U : MF_GRAYED), kMemoryMenuNormalizeHex, L"格式化 Hex");
        ::AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(hexMenu), L"Hex");
    }
    HMENU snapshotMenu = ::CreatePopupMenu();
    if (snapshotMenu) {
        ::AppendMenuW(snapshotMenu,
            MF_STRING | kSnapshotState | (state.snapshotPresentation == SnapshotPresentation::kEditableHex ? MF_CHECKED : 0U),
            kMemoryMenuShowEditableHex, L"可编辑 Hex");
        ::AppendMenuW(snapshotMenu,
            MF_STRING | kSnapshotState | (state.snapshotPresentation == SnapshotPresentation::kHexAscii ? MF_CHECKED : 0U),
            kMemoryMenuShowHexAscii, L"Hex + ASCII");
        ::AppendMenuW(snapshotMenu,
            MF_STRING | kSnapshotState | (state.snapshotPresentation == SnapshotPresentation::kTextRuns ? MF_CHECKED : 0U),
            kMemoryMenuShowTextRuns, L"ASCII / UTF-16LE 文本");
        ::AppendMenuW(snapshotMenu, MF_SEPARATOR, 0, nullptr);
        ::AppendMenuW(snapshotMenu, MF_STRING | kSnapshotState, kMemoryMenuExportSnapshotText, L"导出快照报告 (.txt)");
        ::AppendMenuW(snapshotMenu, MF_STRING | kSnapshotState, kMemoryMenuExportSnapshotBinary, L"导出原始字节 (.bin)");
        ::AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(snapshotMenu), L"读取快照");
    }
    HMENU statusMenu = ::CreatePopupMenu();
    if (statusMenu) {
        ::AppendMenuW(statusMenu, MF_STRING, kMemoryMenuCopyStatus, L"复制状态");
        ::AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(statusMenu), L"状态");
    }

    const UINT kCommand = ::TrackPopupMenu(menu,
        TPM_RETURNCMD | TPM_RIGHTBUTTON,
        screenPoint.x,
        screenPoint.y,
        0,
        state.hwnd,
        nullptr);
    ::DestroyMenu(menu);

    switch (kCommand) {
    case kMemoryMenuRead:
        handleRead(state);
        break;
    case kMemoryMenuWrite:
        handleWrite(state);
        break;
    case kMemoryMenuPreviewDiff:
        prepareWritePlan(state);
        break;
    case kMemoryMenuApplyDiff:
        handleApplyWritePlan(state);
        break;
    case kMemoryMenuSelectAll:
        selectAllEditText(kTextTarget ? target : state.hexEdit);
        break;
    case kMemoryMenuCopyHex:
        setStatus(state, copyTextToClipboard(state.hwnd, getWindowTextString(state.hexEdit)) ? L"已复制内存检视。" : L"复制内存检视失败。");
        break;
    case kMemoryMenuPasteHex:
        replaceEditSelection(state.hexEdit, textFromClipboard(state.hwnd));
        setStatus(state, L"Hex paste requested.");
        break;
    case kMemoryMenuClearHex:
        ::SetWindowTextW(state.hexEdit, L"");
        setStatus(state, L"Hex buffer cleared.");
        break;
    case kMemoryMenuNormalizeHex:
        normalizeHexBuffer(state);
        break;
    case kMemoryMenuShowEditableHex:
        showSnapshotInspection(state, SnapshotPresentation::kEditableHex);
        break;
    case kMemoryMenuShowHexAscii:
        showSnapshotInspection(state, SnapshotPresentation::kHexAscii);
        break;
    case kMemoryMenuShowTextRuns:
        showSnapshotInspection(state, SnapshotPresentation::kTextRuns);
        break;
    case kMemoryMenuExportSnapshotText:
        exportCurrentSnapshotText(state);
        break;
    case kMemoryMenuExportSnapshotBinary:
        exportCurrentSnapshotBinary(state);
        break;
    case kMemoryMenuCopyStatus:
        setStatus(state, copyTextToClipboard(state.hwnd, getWindowTextString(state.statusEdit)) ? L"Status copied." : L"Copy status failed.");
        break;
    default:
        break;
    }
}

std::wstring selectedHistoryCellText(const DriverMemoryViewState& state) {
    const HWND kList = state.historyList.hwnd();
    const int kSelected = kList ? ListView_GetNextItem(kList, -1, LVNI_SELECTED) : -1;
    const auto& visible = state.historyList.visibleIndexes();
    const auto& rows = state.historyList.rows();
    if (kSelected < 0 || static_cast<std::size_t>(kSelected) >= visible.size()) {
        return {};
    }
    const std::size_t kSource = visible[static_cast<std::size_t>(kSelected)];
    if (kSource >= rows.size() || state.historyContextColumn < 0 || static_cast<std::size_t>(state.historyContextColumn) >= rows[kSource].cells.size()) {
        return {};
    }
    return rows[kSource].cells[static_cast<std::size_t>(state.historyContextColumn)];
}

std::wstring selectedHistoryRowsText(const DriverMemoryViewState& state, const bool allVisible) {
    const HWND kList = state.historyList.hwnd();
    const auto& visible = state.historyList.visibleIndexes();
    const auto& rows = state.historyList.rows();
    std::wstring text;
    for (std::size_t item = 0; item < visible.size(); ++item) {
        if (!allVisible && (!kList || (ListView_GetItemState(kList, static_cast<int>(item), LVIS_SELECTED) & LVIS_SELECTED) == 0)) {
            continue;
        }
        const std::size_t kSource = visible[item];
        if (kSource >= rows.size()) {
            continue;
        }
        const auto& cells = rows[kSource].cells;
        for (std::size_t column = 0; column < cells.size(); ++column) {
            if (column != 0) {
                text.push_back(L'\t');
            }
            text += cells[column];
        }
        text += L"\r\n";
    }
    return text;
}

void showMemoryHistoryContextMenu(DriverMemoryViewState& state, POINT screenPoint) {
    const HWND kList = state.historyList.hwnd();
    if (!kList) {
        return;
    }
    POINT clientPoint = screenPoint;
    ::ScreenToClient(kList, &clientPoint);
    LVHITTESTINFO hit{};
    hit.pt = clientPoint;
    const int kItem = ListView_SubItemHitTest(kList, &hit);
    if (kItem >= 0) {
        state.historyContextColumn = hit.iSubItem;
        ListView_SetItemState(kList, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
        ListView_SetItemState(kList, kItem, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
    }
    const bool kHasSelection = ListView_GetNextItem(kList, -1, LVNI_SELECTED) >= 0;
    HMENU menu = ::CreatePopupMenu();
    if (!menu) {
        return;
    }
    ::AppendMenuW(menu, MF_STRING | (kHasSelection ? 0U : MF_GRAYED), kMemoryMenuCopyHistoryCell, L"复制单元格");
    ::AppendMenuW(menu, MF_STRING | (kHasSelection ? 0U : MF_GRAYED), kMemoryMenuCopyHistoryRow, L"复制行");
    ::AppendMenuW(menu, MF_STRING | (!state.historyList.visibleIndexes().empty() ? 0U : MF_GRAYED), kMemoryMenuCopyHistoryVisible, L"复制可见结果");
    const UINT kCommand = ::TrackPopupMenu(menu, TPM_RETURNCMD | TPM_RIGHTBUTTON, screenPoint.x, screenPoint.y, 0, state.hwnd, nullptr);
    ::DestroyMenu(menu);
    if (kCommand == kMemoryMenuCopyHistoryCell) {
        setStatus(state, copyTextToClipboard(state.hwnd, selectedHistoryCellText(state)) ? L"已复制单元格。" : L"复制单元格失败。");
    } else if (kCommand == kMemoryMenuCopyHistoryRow) {
        setStatus(state, copyTextToClipboard(state.hwnd, selectedHistoryRowsText(state, false)) ? L"已复制行。" : L"复制行失败。");
    } else if (kCommand == kMemoryMenuCopyHistoryVisible) {
        setStatus(state, copyTextToClipboard(state.hwnd, selectedHistoryRowsText(state, true)) ? L"已复制可见结果。" : L"复制可见结果失败。");
    }
}

// createChildControls creates every input/output control for the page. Input is
// page state with hwnd set; processing creates edit controls and buttons; no
// value is returned because missing children are handled by normal HWND checks.
void createChildControls(DriverMemoryViewState& state) {
    state.pidEdit = createEdit(state.hwnd, kPidEditId, L"", 0, 0, 0, 0, 0);
    state.addressEdit = createEdit(state.hwnd, kAddressEditId, L"0x0", 0, 0, 0, 0, 0);
    state.lengthEdit = createEdit(state.hwnd, kLengthEditId, L"16", 0, 0, 0, 0, 0);
    state.readButton = ksword::ui::createButton(state.hwnd, kReadButtonId, L"Read", 0, 0, 0, 0);
    state.writeButton = ksword::ui::createButton(state.hwnd, kWriteButtonId, L"Write", 0, 0, 0, 0);
    state.previewDiffButton = ksword::ui::createButton(state.hwnd, kPreviewDiffButtonId, L"预览差异", 0, 0, 0, 0);
    state.applyDiffButton = ksword::ui::createButton(state.hwnd, kApplyDiffButtonId, L"应用差异", 0, 0, 0, 0);
    state.snapshotPreviousButton = ksword::ui::createButton(state.hwnd, kSnapshotPreviousButtonId, L"上一快照", 0, 0, 0, 0);
    state.snapshotNextButton = ksword::ui::createButton(state.hwnd, kSnapshotNextButtonId, L"下一快照", 0, 0, 0, 0);
    state.hexEdit = createEdit(state.hwnd,
        kHexEditId,
        L"",
        0,
        0,
        0,
        0,
        ES_MULTILINE | ES_AUTOVSCROLL | WS_VSCROLL | ES_WANTRETURN);
    ksword::ui::attachTextFindSupport(state.hexEdit);
    state.historyFilter = ksword::ui::createFilterBar(state.hwnd, kHistoryFilterId, L"筛选操作、PID、地址、状态", 0, 0, 0, 0);
    state.historyList.create(state.hwnd, kHistoryListId, 0, 0, 0, 0, LVS_SHOWSELALWAYS | LVS_SINGLESEL);
    state.historyList.addColumns(memoryHistoryColumns());
    if (state.historyList.hwnd()) {
        ListView_SetExtendedListViewStyle(state.historyList.hwnd(), LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_GRIDLINES | LVS_EX_LABELTIP);
        ::SendMessageW(state.historyList.hwnd(), WM_SETFONT, reinterpret_cast<WPARAM>(ksword::ui::systemUiFont()), TRUE);
    }
    state.statusEdit = createEdit(state.hwnd,
        kStatusEditId,
        L"Driver-only memory read/write surface. Requests are sent through ArkDriverClient and the shared memory IOCTL protocol.",
        0,
        0,
        0,
        0,
        ES_MULTILINE | ES_AUTOVSCROLL | WS_VSCROLL | ES_READONLY);
    ksword::ui::attachTextFindSupport(state.statusEdit);
}

// driverMemoryViewWndProc dispatches page window messages. Inputs are standard
// Win32 message parameters; processing owns state lifetime, child layout and
// button clicks; output is an LRESULT for DefWindowProcW-compatible handling.
LRESULT CALLBACK driverMemoryViewWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (msg == WM_NCCREATE) {
        auto state = std::make_unique<DriverMemoryViewState>();
        state->hwnd = hwnd;
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(state.release()));
    }

    DriverMemoryViewState* state = stateFromWindow(hwnd);
    switch (msg) {
    case WM_CREATE:
        if (state) {
            createChildControls(*state);
            state->operationTask = std::make_unique<ksword::ui::AsyncSnapshotTask<MemoryOperationSnapshot>>(hwnd, kMsgMemoryOperationCompleted);
            state->historyFilterTask = std::make_unique<ksword::ui::AsyncSnapshotTask<MemoryHistoryFilterResult>>(hwnd, kMsgMemoryHistoryFilterCompleted);
            rebuildMemoryHistory(*state);
            updateSnapshotButtons(*state);
        }
        return 0;
    case WM_SIZE:
        if (state) {
            RECT rc{};
            ::GetClientRect(hwnd, &rc);
            layoutChildren(*state, rc);
        }
        return 0;
    case WM_COMMAND:
        if (state && LOWORD(wParam) == kHistoryFilterId && HIWORD(wParam) == EN_CHANGE) {
            requestMemoryHistoryFilter(*state, ksword::ui::getFilterBarText(state->historyFilter));
            return 0;
        }
        if (state && HIWORD(wParam) == EN_CHANGE) {
            const int kId = LOWORD(wParam);
            if (kId == kPidEditId || kId == kAddressEditId || kId == kHexEditId) {
                invalidatePreparedWritePlan(*state);
                updateSnapshotButtons(*state);
                return 0;
            }
        }
        if (state && HIWORD(wParam) == BN_CLICKED) {
            const int kId = LOWORD(wParam);
            if (kId == kReadButtonId) {
                handleRead(*state);
                return 0;
            }
            if (kId == kWriteButtonId) {
                handleWrite(*state);
                return 0;
            }
            if (kId == kPreviewDiffButtonId) {
                prepareWritePlan(*state);
                return 0;
            }
            if (kId == kApplyDiffButtonId) {
                handleApplyWritePlan(*state);
                return 0;
            }
            if (kId == kSnapshotPreviousButtonId) {
                moveToPreviousSnapshot(*state);
                return 0;
            }
            if (kId == kSnapshotNextButtonId) {
                moveToNextSnapshot(*state);
                return 0;
            }
        }
        break;
    case kMsgMemoryOperationCompleted:
        if (state && state->operationTask && state->operationTask->consume(hwnd, wParam, lParam)) {
            return 0;
        }
        break;
    case kMsgMemoryHistoryFilterCompleted:
        if (state && state->historyFilterTask && state->historyFilterTask->consume(hwnd, wParam, lParam)) {
            return 0;
        }
        break;
    case kMsgMemorySelectProcess:
        return state && selectProcessForMemoryOperations(*state, static_cast<DWORD>(wParam)) ? TRUE : FALSE;
    case WM_NOTIFY: {
        const auto* notify = reinterpret_cast<const NMHDR*>(lParam);
        if (state && notify && notify->idFrom == kHistoryListId) {
            LRESULT result = 0;
            if (state->historyList.handleNotify(*notify, result)) {
                return result;
            }
        }
        break;
    }
    case WM_CONTEXTMENU:
        if (state) {
            POINT pt{ GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam) };
            if (pt.x == -1 && pt.y == -1) {
                RECT rc{};
                ::GetWindowRect(state->hexEdit ? state->hexEdit : hwnd, &rc);
                pt = { rc.left + 16, rc.top + 16 };
            }
            HWND target = reinterpret_cast<HWND>(wParam);
            if (target == state->historyList.hwnd()) {
                showMemoryHistoryContextMenu(*state, pt);
                return 0;
            }
            if (target != state->hexEdit && target != state->statusEdit) {
                target = state->hwnd;
            }
            showMemoryContextMenu(*state, target, pt);
            return 0;
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
        paintLabels(hwnd, dc);
        ::EndPaint(hwnd, &ps);
        return 0;
    }
    case WM_ERASEBKGND:
        return 1;
    case WM_NCDESTROY:
        if (state && state->lifetime) {
            state->lifetime->alive.store(false, std::memory_order_release);
        }
        if (state && state->writebackCancellation) {
            state->writebackCancellation->cancel();
        }
        if (state && state->operationTask) {
            state->operationTask->cancel();
        }
        if (state && state->historyFilterTask) {
            state->historyFilterTask->cancel();
        }
        delete state;
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
        break;
    default:
        break;
    }

    return ::DefWindowProcW(hwnd, msg, wParam, lParam);
}

// registerDriverMemoryViewClass installs the page WNDCLASS once. Input is none;
// processing calls RegisterClassW and accepts already-registered classes; output
// is true when CreateWindowExW can use the class.
bool registerDriverMemoryViewClass() {
    static bool registered = false;
    if (registered) {
        return true;
    }

    WNDCLASSW wc{};
    wc.lpfnWndProc = driverMemoryViewWndProc;
    wc.hInstance = ::GetModuleHandleW(nullptr);
    wc.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = ksword::ui::appTheme().windowBrush();
    wc.lpszClassName = kDriverMemoryViewClass;
    if (::RegisterClassW(&wc) || ::GetLastError() == ERROR_CLASS_ALREADY_EXISTS) {
        registered = true;
    }
    return registered;
}

} // namespace

HWND createDriverMemoryView(HWND parent, const RECT& bounds) {
    if (!registerDriverMemoryViewClass()) {
        return nullptr;
    }

    return ::CreateWindowExW(0,
        kDriverMemoryViewClass,
        L"Driver Memory",
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

bool requestDriverMemoryViewProcess(HWND page, const DWORD processId) {
    return page != nullptr && processId != 0U &&
        ::SendMessageW(page, kMsgMemorySelectProcess, static_cast<WPARAM>(processId), 0) == TRUE;
}

} // namespace Ksword::Features::Memory

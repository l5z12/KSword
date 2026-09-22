#include "EtwMonitorView.h"

#include "../../ui/Controls.h"
#include "../../ui/EntityNavigation.h"
#include "../../ui/FilterBar.h"
#include "../../ui/ExportUtil.h"
#include "../../ui/TextFindSupport.h"
#include "../../ui/Theme.h"
#include "EtwFilterDialog.h"

#include <commctrl.h>
#include <shellapi.h>
#include <windowsx.h>
#include <algorithm>
#include <cstdio>
#include <cwctype>
#include <iomanip>
#include <iterator>
#include <regex>
#include <sstream>
#include <string_view>
#include <vector>

namespace ksword::features::monitor {
namespace {

constexpr wchar_t kEtwMonitorViewClass[] = L"KswordARKLight.EtwMonitorView";
constexpr int kStartButtonId = 52001;
constexpr int kStopButtonId = 52002;
constexpr int kFilterButtonId = 52003;
constexpr int kClearButtonId = 52004;
constexpr int kExportButtonId = 52007;
constexpr int kListId = 52005;
constexpr int kLocalFilterBarId = 52006;
constexpr UINT kStatusMessage = WM_APP + 62;
constexpr UINT kLocalFilterMessage = WM_APP + 63;
constexpr UINT kExternalProcessFilterMessage = WM_APP + 64;
constexpr UINT_PTR kEventFlushTimerId = 52061;
constexpr UINT kEventFlushIntervalMs = 150;
constexpr std::size_t kMaxEventRows = 5000;
constexpr std::size_t kMaxEventsPerFlush = 200;
constexpr wchar_t kEtwEventDetailClass[] = L"KswordARKLight.EtwEventDetail";
constexpr UINT kEtwMenuDetail = 52601;
constexpr UINT kEtwMenuCopyRow = 52602;
constexpr UINT kEtwMenuCopyDetail = 52603;
constexpr UINT kEtwMenuClear = 52604;
constexpr UINT kEtwMenuStart = 52605;
constexpr UINT kEtwMenuStop = 52606;
constexpr UINT kEtwMenuFilter = 52607;
constexpr UINT kEtwMenuCopyCell = 52608;
constexpr UINT kEtwMenuCopyVisible = 52609;
constexpr UINT kEtwMenuOpenProcess = 52610;
constexpr UINT kEtwMenuExportVisible = 52611;

void ensureViewClass() {
    static bool registered = false;
    if (registered) {
        return;
    }
    WNDCLASSW wc{};
    wc.lpfnWndProc = &EtwMonitorView::wndProc;
    wc.hInstance = ::GetModuleHandleW(nullptr);
    wc.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = ksword::ui::appTheme().windowBrush();
    wc.lpszClassName = kEtwMonitorViewClass;
    ::RegisterClassW(&wc);
    registered = true;
}

// detailWindowProc owns a small read-only detail window used by ETW row
// double-click. Inputs are ordinary Win32 messages; processing creates and
// resizes one multiline EDIT child containing the supplied text; output is the
// standard message LRESULT.
LRESULT CALLBACK detailWindowProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_NCCREATE: {
        const auto* create = reinterpret_cast<const CREATESTRUCTW*>(lParam);
        auto* text = static_cast<std::wstring*>(create ? create->lpCreateParams : nullptr);
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(text));
        return TRUE;
    }
    case WM_CREATE: {
        auto* text = reinterpret_cast<std::wstring*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
        HWND edit = ::CreateWindowExW(WS_EX_CLIENTEDGE,
            L"EDIT",
            text ? text->c_str() : L"",
            WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL | ES_MULTILINE | ES_AUTOVSCROLL | ES_AUTOHSCROLL | ES_READONLY,
            0,
            0,
            0,
            0,
            hwnd,
            nullptr,
            ::GetModuleHandleW(nullptr),
            nullptr);
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(edit));
        if (edit != nullptr) {
            ::SendMessageW(edit, WM_SETFONT, reinterpret_cast<WPARAM>(ksword::ui::systemUiFont()), TRUE);
            ksword::ui::attachTextFindSupport(edit);
        }
        delete text;
        return 0;
    }
    case WM_SIZE: {
        HWND edit = reinterpret_cast<HWND>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
        if (edit != nullptr) {
            ::MoveWindow(edit, 0, 0, LOWORD(lParam), HIWORD(lParam), TRUE);
        }
        return 0;
    }
    case WM_CLOSE:
        ::DestroyWindow(hwnd);
        return 0;
    default:
        break;
    }
    return ::DefWindowProcW(hwnd, msg, wParam, lParam);
}

// ensureDetailWindowClass registers the ETW detail window class once. Input is
// none; processing is idempotent; no value is returned.
void ensureDetailWindowClass() {
    static bool registered = false;
    if (registered) {
        return;
    }
    WNDCLASSW wc{};
    wc.lpfnWndProc = detailWindowProc;
    wc.hInstance = ::GetModuleHandleW(nullptr);
    wc.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
    wc.lpszClassName = kEtwEventDetailClass;
    ::RegisterClassW(&wc);
    registered = true;
}

void insertColumn(HWND list, int index, const wchar_t* title, int width) {
    LVCOLUMNW column{};
    column.mask = LVCF_TEXT | LVCF_WIDTH;
    column.pszText = const_cast<LPWSTR>(title);
    column.cx = width;
    ListView_InsertColumn(list, index, &column);
}

std::wstring numberText(const unsigned long long value) {
    wchar_t buffer[64] = {};
    std::swprintf(buffer, std::size(buffer), L"%llu", value);
    return buffer;
}

bool containsCaseInsensitive(const std::wstring& value, const std::wstring& query) {
    if (query.empty()) {
        return true;
    }
    const auto kFound = std::search(value.begin(), value.end(), query.begin(), query.end(), [](const wchar_t left, const wchar_t right) {
        return std::towlower(left) == std::towlower(right);
    });
    return kFound != value.end();
}

// matchesEvent tests one captured event against the current query. Events are
// matched field by field instead of through the shared row filter because the
// ETW table is fed from a live ring of EtwEvent records rather than from a
// materialized VirtualListRow snapshot. A non-null pattern means the ".*" toggle
// is on and the expression compiled.
bool matchesEvent(const EtwEvent& eventRow, const std::wstring& query, const std::wregex* pattern) {
    constexpr std::wstring_view kPidPrefix = L"pid:";
    if (query.size() > kPidPrefix.size() && query.compare(0, kPidPrefix.size(), kPidPrefix) == 0) {
        return query.substr(kPidPrefix.size()) == numberText(eventRow.processId);
    }
    const auto kMatches = [&query, pattern](const std::wstring& text) {
        return pattern != nullptr ? std::regex_search(text, *pattern) : containsCaseInsensitive(text, query);
    };
    return kMatches(numberText(eventRow.processId)) ||
        kMatches(eventRow.timeText) ||
        kMatches(eventRow.providerText) ||
        kMatches(numberText(eventRow.threadId)) ||
        kMatches(numberText(eventRow.eventId)) ||
        kMatches(numberText(eventRow.level)) ||
        kMatches(eventRow.summary);
}

// copyTextToClipboard writes Unicode text for ETW menu actions. Inputs are owner
// HWND and text; processing transfers CF_UNICODETEXT to the system clipboard;
// output reports success.
bool copyTextToClipboard(HWND owner, const std::wstring& text) {
    return ksword::ui::copyTextToClipboard(owner, text, L"ETW 监控");
}

} // namespace

EtwMonitorView::EtwMonitorView() = default;

EtwMonitorView::~EtwMonitorView() {
    controller_.stop();
    if (eventImageList_ != nullptr) {
        ImageList_Destroy(eventImageList_);
        eventImageList_ = nullptr;
    }
}

bool EtwMonitorView::create(HWND parent, const RECT& bounds) {
    ensureViewClass();
    hwnd_ = ::CreateWindowExW(
        0,
        kEtwMonitorViewClass,
        L"ETW Monitor",
        WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN | WS_CLIPSIBLINGS,
        bounds.left,
        bounds.top,
        bounds.right - bounds.left,
        bounds.bottom - bounds.top,
        parent,
        nullptr,
        ::GetModuleHandleW(nullptr),
        this);
    return hwnd_ != nullptr;
}

HWND EtwMonitorView::hwnd() const {
    return hwnd_;
}

void EtwMonitorView::setDeleteOnDestroy(const bool enabled) {
    deleteOnDestroy_ = enabled;
}

LRESULT CALLBACK EtwMonitorView::wndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    EtwMonitorView* view = reinterpret_cast<EtwMonitorView*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    if (msg == WM_NCCREATE) {
        auto* cs = reinterpret_cast<CREATESTRUCTW*>(lParam);
        view = cs ? static_cast<EtwMonitorView*>(cs->lpCreateParams) : nullptr;
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(view));
        if (view != nullptr) {
            view->hwnd_ = hwnd;
        }
    }
    return view != nullptr ? view->handleMessage(hwnd, msg, wParam, lParam) : ::DefWindowProcW(hwnd, msg, wParam, lParam);
}

LRESULT EtwMonitorView::handleMessage(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE:
        createControls();
        layout();
        ::SetTimer(hwnd_, kEventFlushTimerId, kEventFlushIntervalMs, nullptr);
        updateButtonState();
        return 0;
    case WM_SIZE:
        layout();
        return 0;
    case WM_COMMAND:
        if (LOWORD(wParam) == kLocalFilterBarId && HIWORD(wParam) == EN_CHANGE) {
            requestLocalFilter(ksword::ui::getFilterBarText(localFilterBar_));
            return 0;
        }
        if (LOWORD(wParam) == kStartButtonId) {
            startSession();
            return 0;
        }
        if (LOWORD(wParam) == kStopButtonId) {
            stopSession();
            return 0;
        }
        if (LOWORD(wParam) == kFilterButtonId) {
            openFilterDialog();
            return 0;
        }
        if (LOWORD(wParam) == kClearButtonId) {
            clearPendingEvents();
            eventRows_.clear();
            clearEventList();
            return 0;
        }
        if (LOWORD(wParam) == kExportButtonId) {
            exportVisibleEventRows();
            return 0;
        }
        break;
    case WM_NOTIFY:
        if (const auto* header = reinterpret_cast<const NMHDR*>(lParam);
            header != nullptr && header->hwndFrom == eventList_ && header->code == LVN_GETDISPINFOW) {
            handleVirtualEventDisplayInfo(reinterpret_cast<NMLVDISPINFOW*>(lParam));
            return 0;
        }
        if (const auto* header = reinterpret_cast<const NMHDR*>(lParam);
            header != nullptr && header->hwndFrom == eventList_ && header->code == NM_DBLCLK) {
            openSelectedEventDetail();
            return 0;
        }
        if (const auto* header = reinterpret_cast<const NMHDR*>(lParam);
            header != nullptr && header->hwndFrom == eventList_ && header->code == NM_RCLICK) {
            POINT pt{};
            ::GetCursorPos(&pt);
            showEventContextMenu(pt);
            return 0;
        }
        break;
    case WM_CONTEXTMENU:
        if (reinterpret_cast<HWND>(wParam) == eventList_) {
            POINT pt{ GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam) };
            if (pt.x == -1 && pt.y == -1) {
                RECT rc{};
                ::GetWindowRect(eventList_, &rc);
                pt = { rc.left + 24, rc.top + 24 };
            }
            showEventContextMenu(pt);
            return 0;
        }
        break;
    case WM_TIMER:
        if (wParam == kEventFlushTimerId) {
            flushPendingEvents();
            return 0;
        }
        break;
    case kStatusMessage: {
        auto* statusText = reinterpret_cast<std::wstring*>(lParam);
        if (statusText != nullptr) {
            updateStatusText(*statusText);
            updateButtonState();
            delete statusText;
        }
        return 0;
    }
    case kLocalFilterMessage:
        if (localFilterTask_ && localFilterTask_->consume(hwnd, wParam, lParam)) {
            return 0;
        }
        break;
    case kExternalProcessFilterMessage:
        if (wParam != 0 && localFilterBar_) {
            const std::wstring kQuery = L"pid:" + std::to_wstring(static_cast<DWORD>(wParam));
            ksword::ui::setFilterBarText(localFilterBar_, kQuery, false);
            requestLocalFilter(kQuery);
            ksword::ui::focusFilterBar(localFilterBar_);
            return 1;
        }
        return 0;
    case WM_CTLCOLORSTATIC: {
        HDC dc = reinterpret_cast<HDC>(wParam);
        ::SetBkMode(dc, TRANSPARENT);
        ::SetTextColor(dc, ksword::ui::appTheme().textColor);
        return reinterpret_cast<LRESULT>(ksword::ui::appTheme().windowBrush());
    }
    case WM_DESTROY:
        ::KillTimer(hwnd_, kEventFlushTimerId);
        if (localFilterTask_) {
            localFilterTask_->cancel();
        }
        controller_.stop();
        return 0;
    case WM_NCDESTROY:
        if (deleteOnDestroy_) {
            ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
            delete this;
            return 0;
        }
        break;
    default:
        break;
    }
    return ::DefWindowProcW(hwnd, msg, wParam, lParam);
}

void EtwMonitorView::createControls() {
    startButton_ = ksword::ui::createButton(hwnd_, kStartButtonId, L"开始", 12, 12, 78, 28);
    stopButton_ = ksword::ui::createButton(hwnd_, kStopButtonId, L"停止", 96, 12, 78, 28);
    filterButton_ = ksword::ui::createButton(hwnd_, kFilterButtonId, L"筛选器...", 180, 12, 96, 28);
    clearButton_ = ksword::ui::createButton(hwnd_, kClearButtonId, L"清空", 282, 12, 78, 28);
    exportButton_ = ksword::ui::createButton(hwnd_, kExportButtonId, L"导出...", 366, 12, 88, 28);
    statusText_ = ksword::ui::createText(hwnd_, 0, L"ETW 已停止。筛选器在弹窗中配置。", 470, 18, 520, 22);
    localFilterBar_ = ksword::ui::createFilterBar(hwnd_, kLocalFilterBarId, L"本地筛选所有事件字段和摘要", 12, 46, 320, 24);

    eventList_ = ::CreateWindowExW(
        WS_EX_CLIENTEDGE,
        WC_LISTVIEWW,
        L"",
        WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SHOWSELALWAYS | LVS_SINGLESEL | LVS_OWNERDATA,
        12,
        76,
        860,
        400,
        hwnd_,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(kListId)),
        ::GetModuleHandleW(nullptr),
        nullptr);
    ListView_SetExtendedListViewStyle(eventList_, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);
    eventImageList_ = ImageList_Create(::GetSystemMetrics(SM_CXSMICON),
        ::GetSystemMetrics(SM_CYSMICON),
        ILC_COLOR32 | ILC_MASK,
        64,
        64);
    if (eventImageList_ != nullptr) {
        ListView_SetImageList(eventList_, eventImageList_, LVSIL_SMALL);
    }
    insertColumn(eventList_, 0, L"PID", 96);
    insertColumn(eventList_, 1, L"时间", 160);
    insertColumn(eventList_, 2, L"Provider", 285);
    insertColumn(eventList_, 3, L"TID", 70);
    insertColumn(eventList_, 4, L"EventId", 70);
    insertColumn(eventList_, 5, L"Level", 60);
    insertColumn(eventList_, 6, L"摘要", 420);
    ::SendMessageW(eventList_, WM_SETFONT, reinterpret_cast<WPARAM>(ksword::ui::systemUiFont()), TRUE);
    localFilterTask_ = std::make_unique<ksword::ui::AsyncSnapshotTask<EtwEventFilterResult>>(hwnd_, kLocalFilterMessage);

    controller_.setEventCallback([this](const EtwEvent& eventRow) {
        enqueueEventFromWorker(eventRow);
    });
    controller_.setStatusCallback([this](const std::wstring& text) {
        if (hwnd_ != nullptr) {
            ::PostMessageW(hwnd_, kStatusMessage, 0, reinterpret_cast<LPARAM>(new std::wstring(text)));
        }
    });
}

void EtwMonitorView::layout() {
    RECT rc{};
    ::GetClientRect(hwnd_, &rc);
    const int kWidth = rc.right - rc.left;
    const int kHeight = rc.bottom - rc.top;
    ::MoveWindow(statusText_, 470, 17, kWidth - 482, 24, TRUE);
    ::MoveWindow(localFilterBar_, 12, 46, kWidth - 24, 24, TRUE);
    ::MoveWindow(eventList_, 12, 76, kWidth - 24, kHeight - 88, TRUE);
}

void EtwMonitorView::startSession() {
    if (controller_.running()) {
        return;
    }
    updateStatusText(L"正在启动 ETW...");
    if (!controller_.start(filterModel_.state())) {
        updateStatusText(controller_.lastError());
    }
    updateButtonState();
}

void EtwMonitorView::stopSession() {
    controller_.stop();
    flushPendingEvents();
    updateButtonState();
}

void EtwMonitorView::openFilterDialog() {
    EtwFilterState editedState = filterModel_.state();
    EtwFilterDialog dialog(hwnd_, editedState);
    if (dialog.showModal(editedState)) {
        filterModel_.setState(editedState);
        updateStatusText(controller_.running()
            ? L"筛选器已更新；重新开始 ETW 后对 Provider 生效。"
            : L"筛选器已更新。");
    }
}

void EtwMonitorView::enqueueEventFromWorker(const EtwEvent& eventRow) {
    // enqueueEventFromWorker intentionally does not touch HWND/ListView state:
    // - input: one ETW row on the ETW processing thread;
    // - processing: bounded append to a private queue protected by a mutex;
    // - return: none.  WM_TIMER later performs all UI work on the UI thread.
    std::lock_guard<std::mutex> lock(pendingEventMutex_);
    pendingEvents_.push_back(eventRow);
    while (pendingEvents_.size() > kMaxEventRows) {
        pendingEvents_.pop_front();
    }
}

void EtwMonitorView::flushPendingEvents() {
    // flushPendingEvents is the only high-volume UI update path:
    // - input: queued ETW rows accumulated by worker callbacks;
    // - processing: drain at most kMaxEventsPerFlush rows per timer tick;
    // - return: none.  Remaining rows stay queued for the next timer tick.
    std::vector<EtwEvent> batch;
    {
        std::lock_guard<std::mutex> lock(pendingEventMutex_);
        const std::size_t kTakeCount = std::min<std::size_t>(pendingEvents_.size(), kMaxEventsPerFlush);
        batch.reserve(kTakeCount);
        for (std::size_t index = 0; index < kTakeCount; ++index) {
            batch.push_back(std::move(pendingEvents_.front()));
            pendingEvents_.pop_front();
        }
    }

    if (!batch.empty()) {
        appendEventsToView(batch);
    }
}

void EtwMonitorView::clearPendingEvents() {
    // clearPendingEvents supports the explicit "clear list" command only:
    // - input: none;
    // - processing: discard queued rows that have not reached the ListView;
    // - return: none.  Historical rendered rows are cleared by the caller.
    std::lock_guard<std::mutex> lock(pendingEventMutex_);
    pendingEvents_.clear();
}

void EtwMonitorView::requestLocalFilter(std::wstring query) {
    localFilterQuery_ = std::move(query);
    localFilterUseRegex_ = ksword::ui::getFilterBarRegexEnabled(localFilterBar_);
    if (eventList_ == nullptr) {
        return;
    }
    if (localFilterQuery_.empty()) {
        visibleEventIndexes_.resize(eventRows_.size());
        for (std::size_t index = 0; index < visibleEventIndexes_.size(); ++index) {
            visibleEventIndexes_[index] = index;
        }
        ListView_SetItemCountEx(eventList_, static_cast<int>(visibleEventIndexes_.size()), LVSICF_NOINVALIDATEALL | LVSICF_NOSCROLL);
        ::InvalidateRect(eventList_, nullptr, FALSE);
        return;
    }
    if (!localFilterTask_) {
        return;
    }
    const auto kSnapshot = std::make_shared<const std::vector<EtwEvent>>(eventRows_);
    const std::uint64_t kGeneration = eventGeneration_;
    const bool kUseRegex = localFilterUseRegex_;
    localFilterTask_->request(
        [kSnapshot, kGeneration, kUseRegex, query = localFilterQuery_]() mutable {
            EtwEventFilterResult result{};
            result.generation = kGeneration;
            result.query = std::move(query);
            result.useRegex = kUseRegex;
            std::wregex compiled;
            bool regexReady = false;
            if (kUseRegex && !result.query.empty()) {
                try {
                    compiled.assign(result.query, std::regex_constants::ECMAScript | std::regex_constants::icase);
                    regexReady = true;
                } catch (const std::regex_error&) {
                    regexReady = false;
                }
            }
            result.visibleIndexes.reserve(kSnapshot->size());
            for (std::size_t index = 0; index < kSnapshot->size(); ++index) {
                if (matchesEvent((*kSnapshot)[index], result.query, regexReady ? &compiled : nullptr)) {
                    result.visibleIndexes.push_back(index);
                }
            }
            return result;
        },
        [this](std::uint64_t, std::optional<EtwEventFilterResult>&& result, std::exception_ptr error) {
            if (error || !result.has_value()) {
                updateStatusText(L"ETW 本地筛选异常结束，已保留当前可见结果。");
                return;
            }
            applyLocalFilter(std::move(*result));
        });
}

void EtwMonitorView::applyLocalFilter(EtwEventFilterResult result) {
    if (result.generation != eventGeneration_ || result.query != localFilterQuery_ ||
        result.useRegex != localFilterUseRegex_) {
        return;
    }
    visibleEventIndexes_ = std::move(result.visibleIndexes);
    ListView_SetItemCountEx(eventList_, static_cast<int>(visibleEventIndexes_.size()), LVSICF_NOINVALIDATEALL | LVSICF_NOSCROLL);
    updateStatusText(L"ETW 本地筛选结果：" + std::to_wstring(visibleEventIndexes_.size()) + L" 项。");
    ::InvalidateRect(eventList_, nullptr, FALSE);
}

void EtwMonitorView::appendEventsToView(const std::vector<EtwEvent>& events) {
    if (events.empty() || eventList_ == nullptr) {
        return;
    }

    const int kItemCountBefore = static_cast<int>(visibleEventIndexes_.size());
    const bool kFollowTail = kItemCountBefore == 0 ||
        ListView_GetTopIndex(eventList_) + ListView_GetCountPerPage(eventList_) >= kItemCountBefore - 1;
    eventRows_.insert(eventRows_.end(), events.begin(), events.end());
    if (eventRows_.size() > kMaxEventRows) {
        const std::size_t kTrimmed = eventRows_.size() - kMaxEventRows;
        eventRows_.erase(eventRows_.begin(), eventRows_.begin() + static_cast<std::ptrdiff_t>(kTrimmed));
    }
    ++eventGeneration_;
    if (localFilterQuery_.empty()) {
        visibleEventIndexes_.resize(eventRows_.size());
        for (std::size_t index = 0; index < visibleEventIndexes_.size(); ++index) {
            visibleEventIndexes_[index] = index;
        }
    } else {
        requestLocalFilter(localFilterQuery_);
    }
    ListView_SetItemCountEx(eventList_, static_cast<int>(visibleEventIndexes_.size()), LVSICF_NOINVALIDATEALL | LVSICF_NOSCROLL);
    if (kFollowTail && !visibleEventIndexes_.empty()) {
        ListView_EnsureVisible(eventList_, static_cast<int>(visibleEventIndexes_.size() - 1), FALSE);
    }
    ::InvalidateRect(eventList_, nullptr, FALSE);
}

// handleVirtualEventDisplayInfo answers only the ListView's visible-cell
// requests from the bounded event ring. High-frequency ETW flushes now update
// one item count instead of issuing one insert and six text messages per event.
bool EtwMonitorView::handleVirtualEventDisplayInfo(NMLVDISPINFOW* displayInfo) {
    if (displayInfo == nullptr || displayInfo->item.iItem < 0 ||
        static_cast<std::size_t>(displayInfo->item.iItem) >= visibleEventIndexes_.size()) {
        return false;
    }

    const std::size_t kSourceIndex = visibleEventIndexes_[static_cast<std::size_t>(displayInfo->item.iItem)];
    if (kSourceIndex >= eventRows_.size()) {
        return false;
    }
    const EtwEvent& eventRow = eventRows_[kSourceIndex];
    if ((displayInfo->item.mask & LVIF_TEXT) != 0) {
        switch (displayInfo->item.iSubItem) {
        case 0: eventTextScratch_ = numberText(eventRow.processId); break;
        case 1: eventTextScratch_ = eventRow.timeText; break;
        case 2: eventTextScratch_ = eventRow.providerText; break;
        case 3: eventTextScratch_ = numberText(eventRow.threadId); break;
        case 4: eventTextScratch_ = numberText(eventRow.eventId); break;
        case 5: eventTextScratch_ = numberText(eventRow.level); break;
        case 6: eventTextScratch_ = eventRow.summary; break;
        default: eventTextScratch_.clear(); break;
        }
        displayInfo->item.pszText = eventTextScratch_.data();
    }
    if ((displayInfo->item.mask & LVIF_IMAGE) != 0) {
        displayInfo->item.iImage = iconIndexForProcessId(eventRow.processId);
    }
    if ((displayInfo->item.mask & LVIF_PARAM) != 0) {
        displayInfo->item.lParam = static_cast<LPARAM>(kSourceIndex);
    }
    return true;
}

void EtwMonitorView::clearEventList() {
    // clearEventList is used only by explicit user clear actions:
    // - input: none;
    // - processing: reset only the owner-data count;
    // - return: none.  No historical rows are reinserted or repainted.
    visibleEventIndexes_.clear();
    ++eventGeneration_;
    ListView_SetItemCountEx(eventList_, 0, LVSICF_NOINVALIDATEALL | LVSICF_NOSCROLL);
    ::InvalidateRect(eventList_, nullptr, FALSE);
}

void EtwMonitorView::updateStatusText(const std::wstring& text) {
    if (statusText_ != nullptr) {
        ::SetWindowTextW(statusText_, text.c_str());
    }
}

void EtwMonitorView::updateButtonState() {
    const BOOL kRunning = controller_.running() ? TRUE : FALSE;
    ::EnableWindow(startButton_, kRunning ? FALSE : TRUE);
    ::EnableWindow(stopButton_, kRunning ? TRUE : FALSE);
}

int EtwMonitorView::iconIndexForProcessId(std::uint32_t processId) {
    if (eventImageList_ == nullptr) {
        return -1;
    }

    const auto kCached = processIconCache_.find(processId);
    if (kCached != processIconCache_.end()) {
        return kCached->second;
    }

    const std::wstring kImagePath = processImagePath(processId);
    SHFILEINFOW shellInfo{};
    UINT flags = SHGFI_ICON | SHGFI_SMALLICON;
    const wchar_t* queryPath = kImagePath.empty() ? L".exe" : kImagePath.c_str();
    if (kImagePath.empty()) {
        flags |= SHGFI_USEFILEATTRIBUTES;
    }

    int imageIndex = -1;
    if (::SHGetFileInfoW(queryPath,
            kImagePath.empty() ? FILE_ATTRIBUTE_NORMAL : 0,
            &shellInfo,
            sizeof(shellInfo),
            flags) && shellInfo.hIcon != nullptr) {
        imageIndex = ImageList_AddIcon(eventImageList_, shellInfo.hIcon);
        ::DestroyIcon(shellInfo.hIcon);
    }

    processIconCache_[processId] = imageIndex;
    return imageIndex;
}

std::wstring EtwMonitorView::processImagePath(std::uint32_t processId) const {
    if (processId == 0) {
        return {};
    }

    HANDLE process = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, static_cast<DWORD>(processId));
    if (process == nullptr) {
        return {};
    }

    std::wstring path;
    std::vector<wchar_t> buffer(32768, L'\0');
    DWORD length = static_cast<DWORD>(buffer.size());
    if (::QueryFullProcessImageNameW(process, 0, buffer.data(), &length) && length > 0) {
        path.assign(buffer.data(), buffer.data() + length);
    }
    ::CloseHandle(process);
    return path;
}

void EtwMonitorView::openSelectedEventDetail() {
    EtwEvent eventRow;
    if (!selectedEvent(&eventRow)) {
        return;
    }
    showEventDetail(eventRow);
}

// openSelectedEventProcess routes only the numeric PID captured by ETW. ETW
// rows do not carry a stable process creation-time identity, so the receiving
// process page deliberately resolves the PID again and may reject an exited or
// recycled instance rather than claiming it is the historical event owner.
void EtwMonitorView::openSelectedEventProcess() {
    EtwEvent eventRow;
    if (!selectedEvent(&eventRow)) {
        return;
    }
    if (eventRow.processId == 0U) {
        updateStatusText(L"该 ETW 事件没有可导航的进程 PID。");
        return;
    }

    ksword::core::NavigationRequest request{};
    request.target = ksword::core::NavigationTarget::kProcessDetails;
    request.entity.kind = ksword::core::EntityKind::kProcess;
    request.entity.id = eventRow.processId;
    const bool kRouted = ksword::ui::requestEntityNavigation(hwnd_, request);
    updateStatusText(kRouted
        ? L"已请求打开当前 PID " + std::to_wstring(eventRow.processId) + L" 的进程详细信息；历史 ETW 归属会重新校验。"
        : L"无法导航到该 ETW 事件的当前进程实例。");
}

void EtwMonitorView::showEventDetail(const EtwEvent& eventRow) {
    ensureDetailWindowClass();

    auto* text = new std::wstring(formatEventDetailText(eventRow));
    HWND detailWindow = ::CreateWindowExW(WS_EX_APPWINDOW,
        kEtwEventDetailClass,
        L"ETW 监控项详细信息",
        WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN | WS_CLIPSIBLINGS,
        CW_USEDEFAULT,
        CW_USEDEFAULT,
        720,
        520,
        hwnd_,
        nullptr,
        ::GetModuleHandleW(nullptr),
        text);
    if (detailWindow == nullptr) {
        delete text;
        updateStatusText(L"创建监控项详细信息窗口失败。");
        return;
    }

    ::ShowWindow(detailWindow, SW_SHOWNORMAL);
    ::UpdateWindow(detailWindow);
    updateStatusText(L"已打开监控项详细信息。");
}

int EtwMonitorView::selectedEventIndex() const {
    if (eventList_ == nullptr) {
        return -1;
    }
    return ListView_GetNextItem(eventList_, -1, LVNI_SELECTED);
}

bool EtwMonitorView::selectedEvent(EtwEvent* eventRow) const {
    const int kSelected = selectedEventIndex();
    if (kSelected < 0) {
        const_cast<EtwMonitorView*>(this)->updateStatusText(L"没有选中监控项。");
        return false;
    }
    if (kSelected >= static_cast<int>(visibleEventIndexes_.size())) {
        const_cast<EtwMonitorView*>(this)->updateStatusText(L"监控项索引已过期，请刷新列表后重试。");
        return false;
    }
    const std::size_t kSourceIndex = visibleEventIndexes_[static_cast<std::size_t>(kSelected)];
    if (kSourceIndex >= eventRows_.size()) {
        const_cast<EtwMonitorView*>(this)->updateStatusText(L"监控项索引已过期，请刷新列表后重试。");
        return false;
    }
    if (eventRow) {
        *eventRow = eventRows_[kSourceIndex];
    }
    return true;
}

std::wstring EtwMonitorView::formatEventDetailText(const EtwEvent& eventRow) const {
    std::wostringstream detail;
    detail << L"时间: " << eventRow.timeText << L"\r\n"
           << L"Provider: " << eventRow.providerText << L"\r\n"
           << L"PID: " << eventRow.processId << L"\r\n"
           << L"TID: " << eventRow.threadId << L"\r\n"
           << L"EventId: " << eventRow.eventId << L"\r\n"
           << L"Version: " << static_cast<unsigned int>(eventRow.version) << L"\r\n"
           << L"Level: " << static_cast<unsigned int>(eventRow.level) << L"\r\n"
           << L"Opcode: " << static_cast<unsigned int>(eventRow.opcode) << L"\r\n"
           << L"Task: " << eventRow.task << L"\r\n"
           << L"Keyword: 0x" << std::hex << std::uppercase << eventRow.keyword << std::dec << L"\r\n\r\n"
           << L"摘要:\r\n" << eventRow.summary << L"\r\n";
    return detail.str();
}

void EtwMonitorView::copySelectedEventRow() {
    EtwEvent eventRow;
    if (!selectedEvent(&eventRow)) {
        return;
    }
    std::wostringstream row;
    row << eventRow.timeText << L'\t'
        << eventRow.providerText << L'\t'
        << eventRow.processId << L'\t'
        << eventRow.threadId << L'\t'
        << eventRow.eventId << L'\t'
        << static_cast<unsigned int>(eventRow.level) << L'\t'
        << eventRow.summary;
    updateStatusText(copyTextToClipboard(hwnd_, row.str()) ? L"已复制 ETW 行。" : L"复制 ETW 行失败。");
}

void EtwMonitorView::copySelectedEventCell() {
    EtwEvent eventRow;
    if (!selectedEvent(&eventRow)) {
        return;
    }
    std::wstring text;
    switch (eventContextColumn_) {
    case 0: text = numberText(eventRow.processId); break;
    case 1: text = eventRow.timeText; break;
    case 2: text = eventRow.providerText; break;
    case 3: text = numberText(eventRow.threadId); break;
    case 4: text = numberText(eventRow.eventId); break;
    case 5: text = numberText(eventRow.level); break;
    case 6: text = eventRow.summary; break;
    default: break;
    }
    updateStatusText(copyTextToClipboard(hwnd_, text) ? L"已复制 ETW 单元格。" : L"复制 ETW 单元格失败。");
}

void EtwMonitorView::copyVisibleEventRows() {
    std::wostringstream output;
    for (const std::size_t kSourceIndex : visibleEventIndexes_) {
        if (kSourceIndex >= eventRows_.size()) {
            continue;
        }
        const EtwEvent& eventRow = eventRows_[kSourceIndex];
        output << eventRow.timeText << L'\t'
               << eventRow.providerText << L'\t'
               << eventRow.processId << L'\t'
               << eventRow.threadId << L'\t'
               << eventRow.eventId << L'\t'
               << static_cast<unsigned int>(eventRow.level) << L'\t'
               << eventRow.summary << L"\r\n";
    }
    updateStatusText(copyTextToClipboard(hwnd_, output.str()) ? L"已复制 ETW 可见结果。" : L"复制 ETW 可见结果失败。");
}

void EtwMonitorView::exportVisibleEventRows() {
    const std::wstring kText = buildVisibleEtwEventsTsv(eventRows_, visibleEventIndexes_);
    if (kText.empty()) {
        updateStatusText(L"没有可导出的 ETW 可见结果。");
        return;
    }

    std::wstring error;
    const ksword::ui::SaveTextFileResult kResult = ksword::ui::saveUtf8TextFileWithDialog(
        hwnd_,
        L"ksword-arklight-etw.tsv",
        L"导出 ETW 可见结果",
        L"TSV 文件 (*.tsv)\0*.tsv\0所有文件 (*.*)\0*.*\0",
        L"tsv",
        kText,
        &error);
    switch (kResult) {
    case ksword::ui::SaveTextFileResult::kSaved:
        updateStatusText(L"ETW 可见结果已导出，并已记录到证据会话。");
        break;
    case ksword::ui::SaveTextFileResult::kCancelled:
        updateStatusText(L"已取消导出 ETW 可见结果。");
        break;
    case ksword::ui::SaveTextFileResult::kFailed:
        updateStatusText(error.empty() ? L"导出 ETW 可见结果失败。" : error);
        break;
    default:
        break;
    }
}

void EtwMonitorView::copySelectedEventDetail() {
    EtwEvent eventRow;
    if (!selectedEvent(&eventRow)) {
        return;
    }
    updateStatusText(copyTextToClipboard(hwnd_, formatEventDetailText(eventRow)) ? L"已复制 ETW 详情。" : L"复制 ETW 详情失败。");
}

void EtwMonitorView::showEventContextMenu(POINT screenPoint) {
    // showEventContextMenu keeps the ETW-only monitor page compact by grouping
    // event actions and session actions under submenus. Inputs are a screen
    // coordinate from mouse or keyboard context-menu invocation; processing
    // updates the selected row, creates transient HMENU objects, then dispatches
    // the returned command. There is no return value.
    if (eventList_ == nullptr) {
        return;
    }
    POINT clientPoint = screenPoint;
    ::ScreenToClient(eventList_, &clientPoint);
    LVHITTESTINFO hit{};
    hit.pt = clientPoint;
    const int kHitRow = ListView_SubItemHitTest(eventList_, &hit);
    if (kHitRow >= 0) {
        eventContextColumn_ = hit.iSubItem;
        ListView_SetItemState(eventList_, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
        ListView_SetItemState(eventList_, kHitRow, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
    }

    const bool kHasSelection = selectedEventIndex() >= 0;
    EtwEvent selectedRow{};
    const bool kCanOpenProcess = kHasSelection && selectedEvent(&selectedRow) && selectedRow.processId != 0U;
    HMENU menu = ::CreatePopupMenu();
    if (!menu) {
        return;
    }
    HMENU eventMenu = ::CreatePopupMenu();
    if (eventMenu) {
        ::AppendMenuW(eventMenu, MF_STRING | (kHasSelection ? 0U : MF_GRAYED), kEtwMenuDetail, L"详细信息");
        ::AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(eventMenu), L"事件");
    }
    HMENU investigationMenu = ::CreatePopupMenu();
    if (investigationMenu) {
        ::AppendMenuW(investigationMenu, MF_STRING | (kCanOpenProcess ? 0U : MF_GRAYED),
            kEtwMenuOpenProcess, L"打开所属进程详细信息");
        ::AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(investigationMenu), L"关联调查");
    }
    HMENU copyMenu = ::CreatePopupMenu();
    if (copyMenu) {
        ::AppendMenuW(copyMenu, MF_STRING | (kHasSelection ? 0U : MF_GRAYED), kEtwMenuCopyCell, L"复制单元格");
        ::AppendMenuW(copyMenu, MF_STRING | (kHasSelection ? 0U : MF_GRAYED), kEtwMenuCopyRow, L"复制当前行");
        ::AppendMenuW(copyMenu, MF_STRING | (kHasSelection ? 0U : MF_GRAYED), kEtwMenuCopyDetail, L"复制详情");
        ::AppendMenuW(copyMenu, MF_STRING | (!visibleEventIndexes_.empty() ? 0U : MF_GRAYED), kEtwMenuCopyVisible, L"复制可见结果");
        ::AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(copyMenu), L"复制");
    }
    HMENU exportMenu = ::CreatePopupMenu();
    if (exportMenu) {
        ::AppendMenuW(exportMenu, MF_STRING | (!visibleEventIndexes_.empty() ? 0U : MF_GRAYED),
            kEtwMenuExportVisible, L"导出可见结果...");
        ::AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(exportMenu), L"导出");
    }
    HMENU sessionMenu = ::CreatePopupMenu();
    if (sessionMenu) {
        ::AppendMenuW(sessionMenu, MF_STRING | (controller_.running() ? MF_GRAYED : 0U), kEtwMenuStart, L"开始");
        ::AppendMenuW(sessionMenu, MF_STRING | (controller_.running() ? 0U : MF_GRAYED), kEtwMenuStop, L"停止");
        ::AppendMenuW(sessionMenu, MF_STRING, kEtwMenuFilter, L"筛选器...");
        ::AppendMenuW(sessionMenu, MF_SEPARATOR, 0, nullptr);
        ::AppendMenuW(sessionMenu, MF_STRING, kEtwMenuClear, L"清空列表");
        ::AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(sessionMenu), L"ETW 会话");
    }

    const UINT kCommand = ::TrackPopupMenu(menu,
        TPM_RETURNCMD | TPM_RIGHTBUTTON,
        screenPoint.x,
        screenPoint.y,
        0,
        hwnd_,
        nullptr);
    ::DestroyMenu(menu);

    switch (kCommand) {
    case kEtwMenuDetail:
        openSelectedEventDetail();
        break;
    case kEtwMenuOpenProcess:
        openSelectedEventProcess();
        break;
    case kEtwMenuCopyRow:
        copySelectedEventRow();
        break;
    case kEtwMenuCopyCell:
        copySelectedEventCell();
        break;
    case kEtwMenuCopyDetail:
        copySelectedEventDetail();
        break;
    case kEtwMenuCopyVisible:
        copyVisibleEventRows();
        break;
    case kEtwMenuExportVisible:
        exportVisibleEventRows();
        break;
    case kEtwMenuClear:
        clearPendingEvents();
        eventRows_.clear();
        clearEventList();
        updateStatusText(L"ETW 列表已清空。");
        break;
    case kEtwMenuStart:
        startSession();
        break;
    case kEtwMenuStop:
        stopSession();
        break;
    case kEtwMenuFilter:
        openFilterDialog();
        break;
    default:
        break;
    }
}

HWND createEtwMonitorPage(HWND parent, const RECT& bounds) {
    auto* view = new EtwMonitorView();
    if (!view->create(parent, bounds)) {
        delete view;
        return nullptr;
    }
    view->setDeleteOnDestroy(true);
    return view->hwnd();
}

bool requestEtwMonitorProcessFilter(HWND page, const DWORD processId) {
    return page && processId != 0 &&
        ::SendMessageW(page, kExternalProcessFilterMessage, static_cast<WPARAM>(processId), 0) != 0;
}

} // namespace Ksword::Features::Monitor

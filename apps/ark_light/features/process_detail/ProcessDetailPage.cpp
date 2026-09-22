#include "ProcessDetailPage.h"

#include "ProcessDetailCollector.h"

#include "../../ui/Controls.h"
#include "../../ui/ExportUtil.h"
#include "../../ui/LoadingOverlay.h"
#include "../../ui/TextFindSupport.h"
#include "../../ui/Theme.h"

#include <commctrl.h>
#include <windowsx.h>

#include <algorithm>
#include <cstring>
#include <cwchar>
#include <limits>
#include <sstream>
#include <utility>

namespace ksword::features::process_detail {
namespace {

constexpr wchar_t kProcessDetailPageClass[] = L"KswordARKLight.ProcessDetailPage.FullWin32";
constexpr int kRootMargin = 8;
constexpr UINT kCopyCellCommand = 64001;
constexpr UINT kCopyRowCommand = 64002;
constexpr UINT kCopyAllCommand = 64003;
constexpr UINT kMsgSnapshotCompleted = WM_APP + 610;
constexpr UINT kMsgThreadFilterCompleted = WM_APP + 611;
constexpr UINT kMsgModuleFilterCompleted = WM_APP + 612;
constexpr UINT kMsgActionCompleted = WM_APP + 613;
constexpr UINT kMsgTokenReportCompleted = WM_APP + 614;
constexpr UINT kMsgTokenSwitchCompleted = WM_APP + 615;
constexpr UINT kMsgEvidenceCompleted = WM_APP + 616;
constexpr UINT kMsgPebCompleted = WM_APP + 617;
constexpr UINT kMsgHotkeyCompleted = WM_APP + 618;
constexpr UINT kMsgKeyboardCompleted = WM_APP + 619;
constexpr int kSnapshotLoadingOverlayId = 1110;

constexpr std::array<const wchar_t*, 10> kTabTitles{
    L"详细信息",
    L"线程",
    L"操作",
    L"模块",
    L"令牌",
    L"令牌开关",
    L"Process Detail Evidence",
    L"进程热键",
    L"键盘",
    L"PEB"
};

int rectWidth(const RECT& rect) {
    return std::max(0L, rect.right - rect.left);
}

int rectHeight(const RECT& rect) {
    return std::max(0L, rect.bottom - rect.top);
}

bool registerPageClass() {
    WNDCLASSW wc{};
    wc.lpfnWndProc = ProcessDetailPage::windowProc;
    wc.hInstance = ::GetModuleHandleW(nullptr);
    wc.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = ksword::ui::appTheme().windowBrush();
    wc.lpszClassName = kProcessDetailPageClass;
    if (::RegisterClassW(&wc)) {
        return true;
    }
    return ::GetLastError() == ERROR_CLASS_ALREADY_EXISTS;
}

HFONT createTitleFont() {
    LOGFONTW font{};
    HFONT base = ksword::ui::systemUiFont();
    if (base) {
        ::GetObjectW(base, sizeof(font), &font);
    }
    if (font.lfHeight == 0) {
        font.lfHeight = -18;
        wcscpy_s(font.lfFaceName, L"Segoe UI");
    } else {
        font.lfHeight = static_cast<LONG>(font.lfHeight * 1.35);
    }
    font.lfWeight = FW_BOLD;
    return ::CreateFontIndirectW(&font);
}

void insertTab(HWND tab, int index, const wchar_t* title) {
    TCITEMW item{};
    item.mask = TCIF_TEXT;
    item.pszText = const_cast<LPWSTR>(title);
    ::SendMessageW(tab, TCM_INSERTITEMW, static_cast<WPARAM>(index), reinterpret_cast<LPARAM>(&item));
}

} // namespace

ProcessDetailPage::ProcessDetailPage(
    DWORD processId,
    ULONGLONG expectedCreationTime100ns)
    : processId_(processId),
      expectedCreationTime100ns_(expectedCreationTime100ns) {}

ProcessDetailPage::~ProcessDetailPage() {
    if (snapshotTask_) {
        snapshotTask_->cancel();
    }
    if (actionTask_) {
        actionTask_->cancel();
    }
    if (tokenReportTask_) {
        tokenReportTask_->cancel();
    }
    if (tokenSwitchTask_) {
        tokenSwitchTask_->cancel();
    }
    if (evidenceTask_) {
        evidenceTask_->cancel();
    }
    if (pebTask_) {
        pebTask_->cancel();
    }
    if (hotkeyTask_) {
        hotkeyTask_->cancel();
    }
    if (keyboardTask_) {
        keyboardTask_->cancel();
    }
    if (threadFilterTask_) {
        threadFilterTask_->cancel();
    }
    if (moduleFilterTask_) {
        moduleFilterTask_->cancel();
    }
    if (titleFont_) {
        ::DeleteObject(titleFont_);
        titleFont_ = nullptr;
    }
}

HWND ProcessDetailPage::create(
    HWND parent,
    DWORD processId,
    ULONGLONG expectedCreationTime100ns,
    const RECT& bounds) {
    if (!registerPageClass()) {
        return nullptr;
    }
    auto* page = new ProcessDetailPage(processId, expectedCreationTime100ns);
    HWND hwnd = ::CreateWindowExW(
        0,
        kProcessDetailPageClass,
        L"Process Detail",
        WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN | WS_CLIPSIBLINGS,
        bounds.left,
        bounds.top,
        rectWidth(bounds),
        rectHeight(bounds),
        parent,
        nullptr,
        ::GetModuleHandleW(nullptr),
        page);
    if (!hwnd) {
        delete page;
    }
    return hwnd;
}

LRESULT CALLBACK ProcessDetailPage::windowProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam) {
    auto* page = reinterpret_cast<ProcessDetailPage*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    if (message == WM_NCCREATE) {
        const auto* create = reinterpret_cast<const CREATESTRUCTW*>(lParam);
        page = create ? static_cast<ProcessDetailPage*>(create->lpCreateParams) : nullptr;
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(page));
        if (page) {
            page->hwnd_ = hwnd;
        }
    }
    return page ? page->handleMessage(hwnd, message, wParam, lParam)
                : ::DefWindowProcW(hwnd, message, wParam, lParam);
}

LRESULT ProcessDetailPage::handleMessage(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam) {
    switch (message) {
    case WM_CREATE:
        return initialize(hwnd) ? 0 : -1;
    case WM_SIZE:
        layout();
        return 0;
    case kMsgSnapshotCompleted:
        if (snapshotTask_ && snapshotTask_->consume(hwnd, wParam, lParam)) {
            return 0;
        }
        break;
    case kMsgActionCompleted:
        if (actionTask_ && actionTask_->consume(hwnd, wParam, lParam)) {
            return 0;
        }
        break;
    case kMsgTokenReportCompleted:
        if (tokenReportTask_ && tokenReportTask_->consume(hwnd, wParam, lParam)) {
            return 0;
        }
        break;
    case kMsgTokenSwitchCompleted:
        if (tokenSwitchTask_ && tokenSwitchTask_->consume(hwnd, wParam, lParam)) {
            return 0;
        }
        break;
    case kMsgEvidenceCompleted:
        if (evidenceTask_ && evidenceTask_->consume(hwnd, wParam, lParam)) {
            return 0;
        }
        break;
    case kMsgPebCompleted:
        if (pebTask_ && pebTask_->consume(hwnd, wParam, lParam)) {
            return 0;
        }
        break;
    case kMsgHotkeyCompleted:
        if (hotkeyTask_ && hotkeyTask_->consume(hwnd, wParam, lParam)) {
            return 0;
        }
        break;
    case kMsgKeyboardCompleted:
        if (keyboardTask_ && keyboardTask_->consume(hwnd, wParam, lParam)) {
            return 0;
        }
        break;
    case kMsgThreadFilterCompleted:
        if (threadFilterTask_ && threadFilterTask_->consume(hwnd, wParam, lParam)) {
            return 0;
        }
        break;
    case kMsgModuleFilterCompleted:
        if (moduleFilterTask_ && moduleFilterTask_->consume(hwnd, wParam, lParam)) {
            return 0;
        }
        break;
    case WM_NOTIFY:
        if (auto* header = reinterpret_cast<NMHDR*>(lParam);
            header && header->hwndFrom == tab_ && header->code == TCN_SELCHANGE) {
            updateVisiblePage();
            return 0;
        }
        break;
    case WM_CTLCOLORSTATIC:
    case WM_CTLCOLORBTN:
        ::SetBkMode(reinterpret_cast<HDC>(wParam), TRANSPARENT);
        ::SetTextColor(reinterpret_cast<HDC>(wParam), ksword::ui::appTheme().textColor);
        return reinterpret_cast<LRESULT>(ksword::ui::appTheme().windowBrush());
    case WM_NCDESTROY:
        if (snapshotTask_) {
            snapshotTask_->cancel();
        }
        if (actionTask_) {
            actionTask_->cancel();
        }
        if (tokenReportTask_) {
            tokenReportTask_->cancel();
        }
        if (tokenSwitchTask_) {
            tokenSwitchTask_->cancel();
        }
        if (evidenceTask_) {
            evidenceTask_->cancel();
        }
        if (pebTask_) {
            pebTask_->cancel();
        }
        if (hotkeyTask_) {
            hotkeyTask_->cancel();
        }
        if (keyboardTask_) {
            keyboardTask_->cancel();
        }
        if (threadFilterTask_) {
            threadFilterTask_->cancel();
        }
        if (moduleFilterTask_) {
            moduleFilterTask_->cancel();
        }
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
        delete this;
        return 0;
    default:
        break;
    }
    return ::DefWindowProcW(hwnd, message, wParam, lParam);
}

bool ProcessDetailPage::initialize(HWND hwnd) {
    hwnd_ = hwnd;
    titleFont_ = createTitleFont();
    tab_ = ::CreateWindowExW(
        0,
        WC_TABCONTROLW,
        L"",
        WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN | WS_CLIPSIBLINGS | WS_TABSTOP,
        kRootMargin,
        kRootMargin,
        400,
        300,
        hwnd_,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(kTabControl)),
        ::GetModuleHandleW(nullptr),
        nullptr);
    applyFont(tab_);
    if (!tab_) {
        return false;
    }
    if (kTabTitles.size() != static_cast<std::size_t>(TabIndex::kCount)) {
        return false;
    }
    for (int index = 0; index < static_cast<int>(kTabTitles.size()); ++index) {
        insertTab(tab_, index, kTabTitles[static_cast<std::size_t>(index)]);
    }

    loadingOverlay_ = ksword::ui::createLoadingOverlay(hwnd_, kSnapshotLoadingOverlayId, { 0, 0, 1, 1 });
    snapshotTask_ = std::make_unique<ksword::ui::AsyncSnapshotTask<ProcessDetailSnapshot>>(hwnd_, kMsgSnapshotCompleted);
    actionTask_ = std::make_unique<ksword::ui::AsyncSnapshotTask<ProcessDetailActionResult>>(hwnd_, kMsgActionCompleted);
    tokenReportTask_ = std::make_unique<ksword::ui::AsyncSnapshotTask<ProcessTokenReportSnapshot>>(hwnd_, kMsgTokenReportCompleted);
    tokenSwitchTask_ = std::make_unique<ksword::ui::AsyncSnapshotTask<ProcessTokenSwitchSnapshot>>(hwnd_, kMsgTokenSwitchCompleted);
    evidenceTask_ = std::make_unique<ksword::ui::AsyncSnapshotTask<ProcessDetailSnapshot>>(hwnd_, kMsgEvidenceCompleted);
    pebTask_ = std::make_unique<ksword::ui::AsyncSnapshotTask<ProcessPebSnapshot>>(hwnd_, kMsgPebCompleted);
    hotkeyTask_ = std::make_unique<ksword::ui::AsyncSnapshotTask<ProcessHotkeySnapshot>>(hwnd_, kMsgHotkeyCompleted);
    keyboardTask_ = std::make_unique<ksword::ui::AsyncSnapshotTask<KeyboardSnapshot>>(hwnd_, kMsgKeyboardCompleted);
    threadFilterTask_ = std::make_unique<ksword::ui::AsyncSnapshotTask<DetailTableFilterResult>>(hwnd_, kMsgThreadFilterCompleted);
    moduleFilterTask_ = std::make_unique<ksword::ui::AsyncSnapshotTask<DetailTableFilterResult>>(hwnd_, kMsgModuleFilterCompleted);
    if (!loadingOverlay_ || !snapshotTask_ || !actionTask_ || !tokenReportTask_ || !tokenSwitchTask_ || !evidenceTask_ || !pebTask_ || !hotkeyTask_ || !keyboardTask_ || !threadFilterTask_ || !moduleFilterTask_) {
        return false;
    }
    ::SendMessageW(tab_, TCM_SETCURSEL, 0, 0);
    updateVisiblePage();
    beginSnapshotRefresh();
    return true;
}

LRESULT CALLBACK ProcessDetailPage::pageSubclassProc(
    HWND hwnd,
    UINT message,
    WPARAM wParam,
    LPARAM lParam,
    UINT_PTR subclassId,
    DWORD_PTR referenceData) {
    auto* page = reinterpret_cast<ProcessDetailPage*>(referenceData);
    if (!page || subclassId == 0 || subclassId > static_cast<UINT_PTR>(TabIndex::kCount)) {
        return ::DefSubclassProc(hwnd, message, wParam, lParam);
    }
    const TabIndex kTab = static_cast<TabIndex>(subclassId - 1);
    if (message == WM_NCDESTROY) {
        ::RemoveWindowSubclass(hwnd, pageSubclassProc, subclassId);
    }
    return page->handlePageMessage(kTab, hwnd, message, wParam, lParam);
}

LRESULT ProcessDetailPage::handlePageMessage(
    TabIndex tab,
    HWND hwnd,
    UINT message,
    WPARAM wParam,
    LPARAM lParam) {
    switch (message) {
    case WM_SIZE:
        layoutPage(tab);
        return 0;
    case WM_COMMAND: {
        const int kId = LOWORD(wParam);
        bool handled = false;
        switch (tab) {
        case TabIndex::kDetail: handled = handleDetailCommand(kId); break;
        case TabIndex::kThreads: handled = handleThreadCommand(kId); break;
        case TabIndex::kActions: handled = handleActionCommand(kId); break;
        case TabIndex::kModules: handled = handleModuleCommand(kId); break;
        case TabIndex::kToken: handled = handleTokenCommand(kId); break;
        case TabIndex::kTokenSwitch: handled = handleTokenSwitchCommand(kId); break;
        case TabIndex::kEvidence: handled = handleEvidenceCommand(kId); break;
        case TabIndex::kHotkey: handled = handleHotkeyCommand(kId); break;
        case TabIndex::kKeyboard: handled = handleKeyboardCommand(kId); break;
        case TabIndex::kPeb: handled = handlePebCommand(kId); break;
        default: break;
        }
        if (handled) {
            return 0;
        }
        break;
    }
    case WM_NOTIFY: {
        LRESULT result = 0;
        if (handlePageNotify(tab, reinterpret_cast<NMHDR*>(lParam), result)) {
            return result;
        }
        break;
    }
    case WM_CONTEXTMENU: {
        POINT point{ GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam) };
        HWND source = reinterpret_cast<HWND>(wParam);
        if (point.x == -1 && point.y == -1 && source) {
            RECT sourceRect{};
            ::GetWindowRect(source, &sourceRect);
            point = { sourceRect.left + 24, sourceRect.top + 24 };
        }
        if (handleGenericContextMenu(source, point)) {
            return 0;
        }
        break;
    }
    case WM_CTLCOLORSTATIC:
    case WM_CTLCOLORBTN:
        ::SetBkMode(reinterpret_cast<HDC>(wParam), TRANSPARENT);
        ::SetTextColor(reinterpret_cast<HDC>(wParam), ksword::ui::appTheme().textColor);
        return reinterpret_cast<LRESULT>(ksword::ui::appTheme().windowBrush());
    default:
        break;
    }
    return ::DefSubclassProc(hwnd, message, wParam, lParam);
}

void ProcessDetailPage::layout() {
    if (!hwnd_ || !tab_) {
        return;
    }
    RECT client{};
    ::GetClientRect(hwnd_, &client);
    const int kWidth = std::max(0, rectWidth(client) - kRootMargin * 2);
    const int kHeight = std::max(0, rectHeight(client) - kRootMargin * 2);
    ::MoveWindow(tab_, kRootMargin, kRootMargin, kWidth, kHeight, TRUE);

    RECT pageRect{};
    ::GetClientRect(tab_, &pageRect);
    ::SendMessageW(tab_, TCM_ADJUSTRECT, FALSE, reinterpret_cast<LPARAM>(&pageRect));
    for (std::size_t index = 0; index < pages_.size(); ++index) {
        HWND page = pages_[index].hwnd;
        if (page) {
            ::MoveWindow(page, pageRect.left, pageRect.top, rectWidth(pageRect), rectHeight(pageRect), TRUE);
            layoutPage(static_cast<TabIndex>(index));
        }
    }
    if (loadingOverlay_) {
        ::MoveWindow(loadingOverlay_, 0, 0, rectWidth(client), rectHeight(client), TRUE);
    }
}

void ProcessDetailPage::layoutPage(TabIndex tab) {
    PageState& page = pages_[static_cast<std::size_t>(tab)];
    if (!page.hwnd) {
        return;
    }
    RECT client{};
    ::GetClientRect(page.hwnd, &client);
    HDWP deferred = ::BeginDeferWindowPos(static_cast<int>(page.placements.size()));
    for (const Placement& placement : page.placements) {
        if (!placement.hwnd) {
            continue;
        }
        const int kX = placement.x < 0 ? std::max(0, rectWidth(client) + placement.x) : placement.x;
        const int kY = placement.y < 0 ? std::max(0, rectHeight(client) + placement.y) : placement.y;
        const int kWidth = placement.width < 0
            ? std::max(0, rectWidth(client) - kX + placement.width)
            : placement.width;
        const int kHeight = placement.height < 0
            ? std::max(0, rectHeight(client) - kY + placement.height)
            : placement.height;
        if (deferred) {
            deferred = ::DeferWindowPos(
                deferred,
                placement.hwnd,
                nullptr,
                kX,
                kY,
                kWidth,
                kHeight,
                SWP_NOZORDER | SWP_NOACTIVATE);
        } else {
            ::MoveWindow(placement.hwnd, kX, kY, kWidth, kHeight, TRUE);
        }
    }
    if (deferred) {
        ::EndDeferWindowPos(deferred);
    }
}

void ProcessDetailPage::updateVisiblePage() {
    int selected = static_cast<int>(::SendMessageW(tab_, TCM_GETCURSEL, 0, 0));
    if (selected < 0 || selected >= static_cast<int>(TabIndex::kCount)) {
        selected = 0;
    }

    const TabIndex kSelectedTab = static_cast<TabIndex>(selected);
    if (currentTab_ != kSelectedTab && currentTab_ != TabIndex::kCount) {
        destroyPageHost(currentTab_);
    }
    currentTab_ = kSelectedTab;

    if (!ensurePage(kSelectedTab)) {
        return;
    }

    if (HWND page = pages_[static_cast<std::size_t>(kSelectedTab)].hwnd) {
        ::ShowWindow(page, SW_SHOW);
    }
    layout();
    populateTab(kSelectedTab);
    onTabActivated(kSelectedTab);
    redrawTabClient();
}

bool ProcessDetailPage::ensurePage(TabIndex tab) {
    PageState& page = pages_[static_cast<std::size_t>(tab)];
    if (page.hwnd) {
        return true;
    }
    resetTabRuntimeState(tab);
    if (!createPageHost(tab)) {
        return false;
    }
    if (!createTabControls(tab)) {
        destroyPageHost(tab);
        return false;
    }
    layoutPage(tab);
    return true;
}

bool ProcessDetailPage::createPageHost(TabIndex tab) {
    PageState& page = pages_[static_cast<std::size_t>(tab)];
    if (page.hwnd) {
        return true;
    }

    // TabCtrl_AdjustRect returns tab-client coordinates. The page host lives
    // inside the TabControl so the active tab owns all visible child HWNDs.
    HWND pageHwnd = ::CreateWindowExW(
        0,
        WC_STATICW,
        L"",
        WS_CHILD | WS_CLIPCHILDREN | WS_CLIPSIBLINGS,
        0,
        0,
        100,
        100,
        tab_,
        nullptr,
        ::GetModuleHandleW(nullptr),
        nullptr);
    page.hwnd = pageHwnd;
    if (!pageHwnd || !::SetWindowSubclass(
            pageHwnd,
            pageSubclassProc,
            static_cast<UINT_PTR>(static_cast<std::size_t>(tab) + 1),
            reinterpret_cast<DWORD_PTR>(this))) {
        page.hwnd = nullptr;
        if (pageHwnd) {
            ::DestroyWindow(pageHwnd);
        }
        return false;
    }
    return true;
}

void ProcessDetailPage::destroyPageHost(TabIndex tab) {
    PageState& page = pages_[static_cast<std::size_t>(tab)];
    for (const Placement& placement : page.placements) {
        listColumnCounts_.erase(placement.hwnd);
        listContextColumns_.erase(placement.hwnd);
    }

    HWND oldPage = page.hwnd;
    if (tab == TabIndex::kThreads) {
        threadVirtualList_.detach();
    } else if (tab == TabIndex::kModules) {
        moduleVirtualList_.detach();
    }
    page.hwnd = nullptr;
    page.placements.clear();
    resetTabRuntimeState(tab);

    if (oldPage) {
        ::ShowWindow(oldPage, SW_HIDE);
        ::DestroyWindow(oldPage);
    }
    redrawTabClient();
}

bool ProcessDetailPage::createTabControls(TabIndex tab) {
    switch (tab) {
    case TabIndex::kDetail: return createDetailTab();
    case TabIndex::kThreads: return createThreadTab();
    case TabIndex::kActions: return createActionTab();
    case TabIndex::kModules: return createModuleTab();
    case TabIndex::kToken: return createTokenTab();
    case TabIndex::kTokenSwitch: return createTokenSwitchTab();
    case TabIndex::kEvidence: return createEvidenceTab();
    case TabIndex::kHotkey: return createHotkeyTab();
    case TabIndex::kKeyboard: return createKeyboardTab();
    case TabIndex::kPeb: return createPebTab();
    default: return false;
    }
}

void ProcessDetailPage::populateTab(TabIndex tab) {
    switch (tab) {
    case TabIndex::kDetail: populateDetailTab(); break;
    case TabIndex::kThreads: populateThreadTab(); break;
    case TabIndex::kModules: populateModuleTab(); break;
    case TabIndex::kToken: populateTokenTab(); break;
    case TabIndex::kTokenSwitch: populateTokenSwitchTab(); break;
    case TabIndex::kEvidence: populateEvidenceTab(); break;
    case TabIndex::kHotkey: populateHotkeyTab(); break;
    case TabIndex::kKeyboard: populateKeyboardTab(); break;
    case TabIndex::kPeb: populatePebTab(); break;
    case TabIndex::kActions:
    default:
        break;
    }
}

void ProcessDetailPage::resetTabRuntimeState(TabIndex tab) {
    switch (tab) {
    case TabIndex::kToken:
        tokenLoaded_ = false;
        break;
    case TabIndex::kTokenSwitch:
        tokenSwitchLoaded_ = false;
        break;
    case TabIndex::kEvidence:
        sectionLoaded_ = false;
        break;
    case TabIndex::kHotkey:
        hotkeyLoaded_ = false;
        break;
    case TabIndex::kKeyboard:
        keyboardLoaded_ = false;
        break;
    case TabIndex::kPeb:
        pebLoaded_ = false;
        break;
    default:
        break;
    }
}

void ProcessDetailPage::redrawTabClient() {
    if (!tab_) {
        return;
    }
    ::RedrawWindow(
        tab_,
        nullptr,
        nullptr,
        RDW_INVALIDATE | RDW_ERASE | RDW_ALLCHILDREN | RDW_UPDATENOW);
}

void ProcessDetailPage::onTabActivated(TabIndex tab) {
    switch (tab) {
    case TabIndex::kToken:
        if (!tokenLoaded_) { refreshTokenReport(); }
        break;
    case TabIndex::kTokenSwitch:
        if (!tokenSwitchLoaded_) { refreshTokenSwitches(); }
        break;
    case TabIndex::kEvidence:
        if (!sectionLoaded_) { refreshSectionReport(); }
        break;
    case TabIndex::kHotkey:
        if (!hotkeyLoaded_) { refreshHotkeys(); }
        break;
    case TabIndex::kKeyboard:
        if (!keyboardLoaded_) { refreshKeyboard(); }
        break;
    case TabIndex::kPeb:
        if (!pebLoaded_) { refreshPebReport(); }
        break;
    default:
        break;
    }
}

void ProcessDetailPage::refreshAll() {
    beginSnapshotRefresh();
}

// beginSnapshotRefresh schedules the expensive process, thread, module and R0
// evidence queries off the UI thread. AsyncSnapshotTask coalesces repeated
// refreshes and discards out-of-date completions when the page closes.
void ProcessDetailPage::beginSnapshotRefresh(const std::wstring& loadingMessage) {
    if (!snapshotTask_) {
        return;
    }
    ksword::ui::setLoadingOverlay(loadingOverlay_, true, loadingMessage);
    setSnapshotRefreshControlsEnabled(false);
    snapshotTask_->request(
        [processId = processId_, expectedCreationTime100ns = expectedCreationTime100ns_]() {
            ProcessDetailCollector collector;
            return collector.collect(processId, expectedCreationTime100ns);
        },
        [this](std::uint64_t, std::optional<ProcessDetailSnapshot>&& snapshot, std::exception_ptr error) {
            ksword::ui::setLoadingOverlay(loadingOverlay_, false);
            setSnapshotRefreshControlsEnabled(true);
            if (error || !snapshot.has_value()) {
                snapshot_ = {};
                snapshot_.errorText = L"进程详情后台刷新异常结束。请检查目标进程、权限和驱动状态。";
            } else {
                applySnapshot(std::move(*snapshot));
                return;
            }
            if (currentTab_ != TabIndex::kCount && pages_[static_cast<std::size_t>(currentTab_)].hwnd) {
                populateTab(currentTab_);
            }
        });
}

// applySnapshot atomically replaces the UI-facing detail snapshot after the
// worker completed. Controls are populated only for the live tab, so hidden
// tabs never cause eager control creation or message storms.
void ProcessDetailPage::applySnapshot(ProcessDetailSnapshot snapshot) {
    snapshot_ = std::move(snapshot);
    pendingThreadEntries_ = std::make_shared<const std::vector<ProcessThreadInfo>>(std::move(snapshot_.threads));
    pendingModuleEntries_ = std::make_shared<const std::vector<ProcessModuleInfo>>(std::move(snapshot_.modules));
    ++threadSourceGeneration_;
    ++moduleSourceGeneration_;
    requestThreadFilter(true);
    requestModuleFilter(true);
    if (currentTab_ != TabIndex::kCount && pages_[static_cast<std::size_t>(currentTab_)].hwnd) {
        populateTab(currentTab_);
    }
}

void ProcessDetailPage::setSnapshotRefreshControlsEnabled(const bool enabled) {
    if (HWND threadRefresh = findControl(TabIndex::kThreads, kThreadRefresh)) {
        ::EnableWindow(threadRefresh, enabled);
    }
    if (HWND moduleRefresh = findControl(TabIndex::kModules, kModuleRefresh)) {
        ::EnableWindow(moduleRefresh, enabled);
    }
}

// executeBackgroundAction serializes process-detail mutations away from the UI
// thread. Confirmations and selection capture occur before this call; the
// worker receives only immutable IDs/snapshots and completion is discarded when
// the page is destroyed by AsyncSnapshotTask.
void ProcessDetailPage::executeBackgroundAction(
    const TabIndex tab,
    const int statusControlId,
    const std::wstring& workingText,
    std::function<ProcessDetailActionResult()> work) {
    if (!actionTask_ || !work) {
        setPageStatus(tab, statusControlId, L"● 操作任务不可用。");
        return;
    }
    if (actionTask_->running()) {
        setPageStatus(tab, statusControlId, L"● 另一个进程操作正在后台执行。");
        return;
    }
    setPageStatus(tab, statusControlId, workingText);
    setBackgroundActionControlsEnabled(false);
    actionTask_->request(
        std::move(work),
        [this, tab, statusControlId](std::uint64_t, std::optional<ProcessDetailActionResult>&& result, std::exception_ptr error) {
            setBackgroundActionControlsEnabled(true);
            if (error || !result.has_value()) {
                setPageStatus(tab, statusControlId, L"● 后台操作异常结束。");
                return;
            }
            setPageStatus(tab, statusControlId, result->statusText);
            if (!result->dialogText.empty()) {
                ::MessageBoxW(
                    hwnd_,
                    result->dialogText.c_str(),
                    result->dialogTitle.empty() ? L"进程操作" : result->dialogTitle.c_str(),
                    MB_OK | (result->dialogIcon == 0 ? MB_ICONINFORMATION : result->dialogIcon));
            }
            if (result->refreshTokenSwitches) {
                refreshTokenSwitches();
            }
            if (result->refreshTokenReport) {
                refreshTokenReport();
            }
            if (result->refreshPebReport) {
                refreshPebReport();
            }
            if (result->refreshRequired) {
                refreshAll();
            }
        });
}

// setBackgroundActionControlsEnabled keeps the mutation surface idle while the
// shared action worker owns an operation. The status labels and tab navigation
// remain available, so the user can inspect prior data without starting a
// competing process/R0 request.
void ProcessDetailPage::setBackgroundActionControlsEnabled(const bool enabled) {
    constexpr std::array<int, 50> kControls{
        kActionTerminateMode,
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
        kTokenSwitchApply,
        kTokenRawInfoClass,
        kTokenRawInputMode,
        kTokenRawPayload,
        kTokenRawApply,
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
        kPebApply,
        kPebCommandLine,
        kPebImagePath,
        kPebCurrentDirectory,
        kPebEnvironmentName,
        kPebEnvironmentValue,
        kPebImageBase,
        kPebAffinity,
        kPebPriority
    };
    for (const int kControlId : kControls) {
        const TabIndex kTab = kControlId >= kPebRefresh
            ? TabIndex::kPeb
            : kControlId >= kTokenSwitchRefresh ? TabIndex::kTokenSwitch : TabIndex::kActions;
        if (HWND control = findControl(kTab, kControlId)) { ::EnableWindow(control, enabled); }
    }
}

HWND ProcessDetailPage::addControl(
    TabIndex tab,
    DWORD exStyle,
    const wchar_t* className,
    const wchar_t* text,
    DWORD style,
    int controlId,
    int x,
    int y,
    int width,
    int height) {
    PageState& page = pages_[static_cast<std::size_t>(tab)];
    const int kInitialWidth = width < 0 ? 100 : width;
    const int kInitialHeight = height < 0 ? 100 : height;
    HWND child = ::CreateWindowExW(
        exStyle,
        className,
        text ? text : L"",
        WS_CHILD | WS_VISIBLE | style,
        x,
        y,
        kInitialWidth,
        kInitialHeight,
        page.hwnd,
        controlId == 0 ? nullptr : reinterpret_cast<HMENU>(static_cast<INT_PTR>(controlId)),
        ::GetModuleHandleW(nullptr),
        nullptr);
    applyFont(child);
    if (child) {
        page.placements.push_back(Placement{ child, x, y, width, height });
    }
    return child;
}

HWND ProcessDetailPage::addLabel(
    TabIndex tab, int controlId, const wchar_t* text, int x, int y, int width, int height) {
    return addControl(tab, 0, WC_STATICW, text, SS_LEFT | SS_CENTERIMAGE | SS_NOTIFY, controlId, x, y, width, height);
}

HWND ProcessDetailPage::addButton(
    TabIndex tab, int controlId, const wchar_t* text, int x, int y, int width, int height) {
    return addControl(tab, 0, WC_BUTTONW, text, BS_PUSHBUTTON | WS_TABSTOP, controlId, x, y, width, height);
}

HWND ProcessDetailPage::addEdit(
    TabIndex tab,
    int controlId,
    const wchar_t* text,
    bool readOnly,
    bool multiline,
    int x,
    int y,
    int width,
    int height) {
    DWORD style = WS_TABSTOP | ES_LEFT;
    DWORD exStyle = WS_EX_CLIENTEDGE;
    if (readOnly) {
        style |= ES_READONLY;
    }
    if (multiline) {
        style |= ES_MULTILINE | ES_AUTOVSCROLL | ES_AUTOHSCROLL | WS_VSCROLL | WS_HSCROLL;
    } else {
        style |= ES_AUTOHSCROLL;
    }
    HWND edit = addControl(tab, exStyle, WC_EDITW, text, style, controlId, x, y, width, height);
    // Every multi-line pane on this page routes through here, so attaching once
    // covers the detail, evidence, PEB and token dumps in a single place.
    if (multiline) {
        ksword::ui::attachTextFindSupport(edit);
    }
    return edit;
}

HWND ProcessDetailPage::addCombo(TabIndex tab, int controlId, int x, int y, int width, int height) {
    return addControl(
        tab, 0, WC_COMBOBOXW, L"", CBS_DROPDOWNLIST | CBS_HASSTRINGS | WS_VSCROLL | WS_TABSTOP,
        controlId, x, y, width, height);
}

HWND ProcessDetailPage::addCheck(
    TabIndex tab, int controlId, const wchar_t* text, int x, int y, int width, int height) {
    return addControl(tab, 0, WC_BUTTONW, text, BS_AUTOCHECKBOX | WS_TABSTOP, controlId, x, y, width, height);
}

HWND ProcessDetailPage::addGroup(
    TabIndex tab, const wchar_t* text, int x, int y, int width, int height) {
    return addControl(tab, 0, WC_BUTTONW, text, BS_GROUPBOX, 0, x, y, width, height);
}

HWND ProcessDetailPage::addList(TabIndex tab, int controlId, int x, int y, int width, int height) {
    HWND list = addControl(
        tab,
        WS_EX_CLIENTEDGE,
        WC_LISTVIEWW,
        L"",
        LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS | WS_TABSTOP,
        controlId,
        x,
        y,
        width,
        height);
    if (list) {
        ListView_SetExtendedListViewStyle(
            list,
            LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP | LVS_EX_INFOTIP);
    }
    return list;
}

HWND ProcessDetailPage::addVirtualList(
    TabIndex tab,
    int controlId,
    int x,
    int y,
    int width,
    int height,
    ksword::ui::VirtualListView& virtualList) {
    PageState& page = pages_[static_cast<std::size_t>(tab)];
    const int kInitialWidth = width < 0 ? 100 : width;
    const int kInitialHeight = height < 0 ? 100 : height;
    if (!virtualList.create(page.hwnd, controlId, x, y, kInitialWidth, kInitialHeight)) {
        return nullptr;
    }
    HWND list = virtualList.hwnd();
    page.placements.push_back(Placement{ list, x, y, width, height });
    ListView_SetExtendedListViewStyle(
        list,
        LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP | LVS_EX_INFOTIP);
    return list;
}

HWND ProcessDetailPage::findControl(TabIndex tab, int controlId) const {
    const HWND kPage = pages_[static_cast<std::size_t>(tab)].hwnd;
    return kPage ? ::GetDlgItem(kPage, controlId) : nullptr;
}

void ProcessDetailPage::setControlText(TabIndex tab, int controlId, const std::wstring& text) {
    if (HWND control = findControl(tab, controlId)) {
        ::SetWindowTextW(control, text.c_str());
    }
}

std::wstring ProcessDetailPage::controlText(TabIndex tab, int controlId) const {
    return readWindowText(findControl(tab, controlId));
}

void ProcessDetailPage::setPageStatus(TabIndex tab, int controlId, const std::wstring& text) {
    setControlText(tab, controlId, text.size() > 160 ? text.substr(0, 157) + L"..." : text);
}

void ProcessDetailPage::addListColumn(HWND list, int index, const wchar_t* title, int width) {
    if (!list) {
        return;
    }
    LVCOLUMNW column{};
    column.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    column.pszText = const_cast<LPWSTR>(title);
    column.cx = width;
    column.iSubItem = index;
    ListView_InsertColumn(list, index, &column);
}

void ProcessDetailPage::clearList(HWND list) {
    if (list) {
        ListView_DeleteAllItems(list);
    }
}

void ProcessDetailPage::addListRow(
    HWND list,
    int row,
    const std::vector<std::wstring>& values,
    LPARAM data) {
    if (!list || values.empty()) {
        return;
    }
    LVITEMW item{};
    item.mask = LVIF_TEXT | LVIF_PARAM;
    item.iItem = row;
    item.pszText = const_cast<LPWSTR>(values[0].c_str());
    item.lParam = data;
    const int kInserted = ListView_InsertItem(list, &item);
    if (kInserted < 0) {
        return;
    }
    for (int column = 1; column < static_cast<int>(values.size()); ++column) {
        ListView_SetItemText(list, kInserted, column, const_cast<LPWSTR>(values[column].c_str()));
    }
}

std::wstring ProcessDetailPage::listCell(HWND list, int row, int column) {
    if (!list || row < 0 || column < 0) {
        return {};
    }
    std::vector<wchar_t> buffer(8192, L'\0');
    LVITEMW item{};
    item.iSubItem = column;
    item.pszText = buffer.data();
    item.cchTextMax = static_cast<int>(buffer.size());
    ListView_GetItem(list, &item);
    ListView_GetItemText(list, row, column, buffer.data(), static_cast<int>(buffer.size()));
    return buffer.data();
}

bool ProcessDetailPage::copyText(HWND owner, const std::wstring& text) {
    // Keep all explicit detail-table copies in the common evidence path while
    // preserving the existing Unicode clipboard representation.
    return ksword::ui::copyTextToClipboard(owner, text, L"进程详细信息");
}

std::wstring ProcessDetailPage::readWindowText(HWND hwnd) {
    if (!hwnd) {
        return {};
    }
    const int kLength = ::GetWindowTextLengthW(hwnd);
    std::wstring text(static_cast<std::size_t>(std::max(0, kLength)) + 1, L'\0');
    ::GetWindowTextW(hwnd, text.data(), static_cast<int>(text.size()));
    text.resize(std::wcslen(text.c_str()));
    return text;
}

void ProcessDetailPage::applyFont(HWND hwnd, HFONT font) {
    if (hwnd) {
        ::SendMessageW(
            hwnd,
            WM_SETFONT,
            reinterpret_cast<WPARAM>(font ? font : ksword::ui::systemUiFont()),
            TRUE);
    }
}

int ProcessDetailPage::selectedListRow(HWND list) const {
    return list ? ListView_GetNextItem(list, -1, LVNI_SELECTED) : -1;
}

void ProcessDetailPage::copyListCell(HWND list) {
    const int kRow = selectedListRow(list);
    const int kColumn = listContextColumns_.contains(list) ? listContextColumns_[list] : 0;
    copyText(hwnd_, listCell(list, kRow, kColumn));
}

void ProcessDetailPage::copyListRow(HWND list) {
    const int kRow = selectedListRow(list);
    const int kColumns = listColumnCounts_.contains(list) ? listColumnCounts_[list] : 0;
    if (kRow < 0 || kColumns <= 0) {
        return;
    }
    std::wostringstream text;
    for (int column = 0; column < kColumns; ++column) {
        if (column) { text << L'\t'; }
        text << listCell(list, kRow, column);
    }
    copyText(hwnd_, text.str());
}

void ProcessDetailPage::copyListAll(HWND list) {
    const int kRows = list ? ListView_GetItemCount(list) : 0;
    const int kColumns = listColumnCounts_.contains(list) ? listColumnCounts_[list] : 0;
    if (kRows <= 0 || kColumns <= 0) {
        return;
    }
    std::wostringstream text;
    wchar_t headerText[512]{};
    HWND header = ListView_GetHeader(list);
    for (int column = 0; column < kColumns; ++column) {
        HDITEMW item{};
        item.mask = HDI_TEXT;
        item.pszText = headerText;
        item.cchTextMax = static_cast<int>(std::size(headerText));
        Header_GetItem(header, column, &item);
        if (column) { text << L'\t'; }
        text << headerText;
    }
    text << L"\r\n";
    for (int row = 0; row < kRows; ++row) {
        for (int column = 0; column < kColumns; ++column) {
            if (column) { text << L'\t'; }
            text << listCell(list, row, column);
        }
        if (row + 1 < kRows) { text << L"\r\n"; }
    }
    copyText(hwnd_, text.str());
}

bool ProcessDetailPage::handleGenericContextMenu(HWND source, POINT screenPoint) {
    if (!source || !listColumnCounts_.contains(source)) {
        return false;
    }
    POINT clientPoint = screenPoint;
    ::ScreenToClient(source, &clientPoint);
    LVHITTESTINFO hit{};
    hit.pt = clientPoint;
    const int kHitRow = ListView_SubItemHitTest(source, &hit);
    listContextColumns_[source] = hit.iSubItem >= 0 ? hit.iSubItem : 0;
    if (kHitRow >= 0) {
        ListView_SetItemState(source, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
        ListView_SetItemState(source, kHitRow, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
    }
    if (selectedListRow(source) < 0) {
        return true;
    }

    if (source == findControl(TabIndex::kThreads, kThreadList)) {
        return handleThreadContextMenu(screenPoint);
    }
    if (source == findControl(TabIndex::kModules, kModuleList)) {
        return handleModuleContextMenu(screenPoint);
    }

    HMENU menu = ::CreatePopupMenu();
    ::AppendMenuW(menu, MF_STRING, kCopyCellCommand, L"复制当前单元格");
    ::AppendMenuW(menu, MF_STRING, kCopyRowCommand, L"复制当前行");
    ::AppendMenuW(menu, MF_STRING, kCopyAllCommand, L"复制全部");
    const UINT kCommand = ::TrackPopupMenu(
        menu, TPM_RETURNCMD | TPM_RIGHTBUTTON, screenPoint.x, screenPoint.y, 0, hwnd_, nullptr);
    ::DestroyMenu(menu);
    if (kCommand == kCopyCellCommand) { copyListCell(source); }
    if (kCommand == kCopyRowCommand) { copyListRow(source); }
    if (kCommand == kCopyAllCommand) { copyListAll(source); }
    return true;
}

bool ProcessDetailPage::handlePageNotify(TabIndex tab, NMHDR* header, LRESULT& result) {
    if (!header) {
        return false;
    }
    if (tab == TabIndex::kKeyboard &&
        header->hwndFrom == findControl(TabIndex::kKeyboard, kKeyboardInnerTab) &&
        header->code == TCN_SELCHANGE) {
        rebuildKeyboardList();
        result = 0;
        return true;
    }
    if (threadVirtualList_.handleNotify(*header, result) || moduleVirtualList_.handleNotify(*header, result)) {
        return true;
    }
    if (header->code == NM_RCLICK && listColumnCounts_.contains(header->hwndFrom)) {
        POINT point{};
        ::GetCursorPos(&point);
        result = handleGenericContextMenu(header->hwndFrom, point) ? 0 : 1;
        return true;
    }
    if (tab == TabIndex::kThreads && header->hwndFrom == findControl(TabIndex::kThreads, kThreadList) &&
        header->code == NM_DBLCLK) {
        showSelectedThreadSummary();
        result = 0;
        return true;
    }
    return false;
}

const std::vector<ProcessThreadInfo>& ProcessDetailPage::threadEntries() const noexcept {
    static const std::vector<ProcessThreadInfo> kEmpty;
    return threadEntries_ ? *threadEntries_ : kEmpty;
}

const std::vector<ProcessModuleInfo>& ProcessDetailPage::moduleEntries() const noexcept {
    static const std::vector<ProcessModuleInfo> kEmpty;
    return moduleEntries_ ? *moduleEntries_ : kEmpty;
}

std::size_t ProcessDetailPage::latestThreadCount() const noexcept {
    if (pendingThreadEntries_) {
        return pendingThreadEntries_->size();
    }
    return threadEntries().size();
}

} // namespace Ksword::Features::process_detail

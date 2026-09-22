#include "WorkspaceHost.h"

#include "Controls.h"
#include "ModuleDescriptor.h"
#include "PlaceholderPage.h"
#include "TabUtil.h"
#include "Theme.h"

#include <algorithm>
#include <commctrl.h>
#include <memory>
#include <utility>

namespace ksword::ui {
namespace {

constexpr wchar_t kWorkspaceHostClass[] = L"KswordARKLight.WorkspaceHost";
constexpr UINT kMsgMaterialize = WM_APP + 760;

struct WorkspaceSlot final {
    WorkspaceTabDescriptor descriptor;
    HWND page = nullptr;
    bool materialized = false;
    bool materializePosted = false;
    bool materializing = false;
};

struct WorkspaceState final {
    HWND hwnd = nullptr;
    HWND tab = nullptr;
    WorkspaceOptions options;
    std::vector<WorkspaceSlot> slots;
    int activeIndex = 0;
};

WorkspaceState* stateFromWindow(HWND hwnd) noexcept {
    return reinterpret_cast<WorkspaceState*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
}

int width(const RECT& rect) noexcept {
    return rect.right > rect.left ? rect.right - rect.left : 0;
}

int height(const RECT& rect) noexcept {
    return rect.bottom > rect.top ? rect.bottom - rect.top : 0;
}

RECT pageBounds(const WorkspaceState& state) noexcept {
    if (!state.tab) {
        return { 0, 0, 1, 1 };
    }
    return getTabDisplayRect(state.tab);
}

int indexForId(const WorkspaceState& state, const int tabId) noexcept {
    for (int index = 0; index < static_cast<int>(state.slots.size()); ++index) {
        if (state.slots[static_cast<std::size_t>(index)].descriptor.id == tabId) {
            return index;
        }
    }
    return -1;
}

void showActivePage(WorkspaceState& state) {
    for (int index = 0; index < static_cast<int>(state.slots.size()); ++index) {
        HWND page = state.slots[static_cast<std::size_t>(index)].page;
        if (page) {
            ::ShowWindow(page, index == state.activeIndex ? SW_SHOW : SW_HIDE);
        }
    }
}

void layout(WorkspaceState& state) {
    if (!state.hwnd || !state.tab) {
        return;
    }
    RECT client{};
    ::GetClientRect(state.hwnd, &client);
    const int kMargin = (std::max)(0, state.options.margin);
    ::MoveWindow(state.tab, kMargin, kMargin,
        (std::max)(1, width(client) - kMargin * 2),
        (std::max)(1, height(client) - kMargin * 2), TRUE);
    const RECT kPageBounds = pageBounds(state);
    for (WorkspaceSlot& slot : state.slots) {
        if (slot.page) {
            ::MoveWindow(slot.page, kPageBounds.left, kPageBounds.top,
                (std::max)(1, width(kPageBounds)), (std::max)(1, height(kPageBounds)), TRUE);
        }
    }
    showActivePage(state);
}

HWND ensurePlaceholder(WorkspaceState& state, const int index) {
    if (index < 0 || index >= static_cast<int>(state.slots.size())) {
        return nullptr;
    }
    WorkspaceSlot& slot = state.slots[static_cast<std::size_t>(index)];
    if (slot.page) {
        return slot.page;
    }
    const RECT kBounds = pageBounds(state);
    ModuleDescriptor descriptor{};
    descriptor.commandId = slot.descriptor.id;
    descriptor.title = slot.descriptor.title;
    descriptor.summary = slot.descriptor.summary.empty() ? L"页面将在首次打开时按需创建。" : slot.descriptor.summary;
    slot.page = createPlaceholderPage(state.tab, descriptor, kBounds);
    return slot.page;
}

HWND materialize(WorkspaceState& state, const int index) {
    if (index < 0 || index >= static_cast<int>(state.slots.size())) {
        return nullptr;
    }
    WorkspaceSlot& slot = state.slots[static_cast<std::size_t>(index)];
    if (slot.materialized) {
        return slot.page;
    }
    if (slot.materializing) {
        return slot.page;
    }
    slot.materializing = true;
    HWND placeholder = ensurePlaceholder(state, index);
    if (placeholder) {
        setPlaceholderPageProgress(placeholder, L"正在创建“" + slot.descriptor.title + L"”页面…", 35);
    }
    const RECT kBounds = pageBounds(state);
    HWND page = slot.descriptor.createPage
        ? slot.descriptor.createPage(state.tab, kBounds)
        : nullptr;
    if (!page) {
        slot.materializing = false;
        if (placeholder) {
            setPlaceholderPageLoading(placeholder, false, L"页面创建失败；再次切换到此页可重试。");
        }
        return nullptr;
    }
    if (placeholder && placeholder != page) {
        ::DestroyWindow(placeholder);
    }
    slot.page = page;
    slot.materialized = true;
    slot.materializing = false;
    layout(state);
    if (state.options.pageActivated && index == state.activeIndex) {
        state.options.pageActivated(slot.descriptor.id, page);
    }
    return page;
}

void activateIndex(WorkspaceState& state, const int index, const bool synchronous) {
    if (index < 0 || index >= static_cast<int>(state.slots.size())) {
        return;
    }
    state.activeIndex = index;
    ::SendMessageW(state.tab, TCM_SETCURSEL, static_cast<WPARAM>(index), 0);
    WorkspaceSlot& slot = state.slots[static_cast<std::size_t>(index)];
    ensurePlaceholder(state, index);
    layout(state);
    if (slot.materialized) {
        if (state.options.pageActivated) {
            state.options.pageActivated(slot.descriptor.id, slot.page);
        }
        return;
    }
    if (synchronous) {
        materialize(state, index);
    } else if (!slot.materializing && !slot.materializePosted) {
        slot.materializePosted = true;
        if (slot.page) {
            setPlaceholderPageProgress(slot.page, L"准备加载“" + slot.descriptor.title + L"”…", 8);
        }
        ::PostMessageW(state.hwnd, kMsgMaterialize, static_cast<WPARAM>(index), 0);
    }
}

LRESULT CALLBACK workspaceProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam) {
    WorkspaceState* state = stateFromWindow(hwnd);
    if (message == WM_NCCREATE) {
        const auto* create = reinterpret_cast<const CREATESTRUCTW*>(lParam);
        state = create ? static_cast<WorkspaceState*>(create->lpCreateParams) : nullptr;
        if (state) {
            state->hwnd = hwnd;
            ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(state));
        }
    }
    switch (message) {
    case WM_CREATE:
        if (!state || state->slots.empty()) {
            return -1;
        }
        state->tab = createTabControl(hwnd, state->options.tabControlId, 0, 0, 1, 1);
        if (!state->tab) {
            return -1;
        }
        for (int index = 0; index < static_cast<int>(state->slots.size()); ++index) {
            addTabPage(state->tab, index, { state->slots[static_cast<std::size_t>(index)].descriptor.title,
                static_cast<LPARAM>(state->slots[static_cast<std::size_t>(index)].descriptor.id) });
        }
        state->activeIndex = indexForId(*state, state->options.initialTabId);
        if (state->activeIndex < 0) {
            state->activeIndex = 0;
        }
        setWindowFontRecursive(hwnd);
        layout(*state);
        activateIndex(*state, state->activeIndex, false);
        return 0;
    case WM_SIZE:
        if (state) {
            layout(*state);
        }
        return 0;
    case WM_NOTIFY:
        if (state) {
            const auto* header = reinterpret_cast<const NMHDR*>(lParam);
            if (header && header->hwndFrom == state->tab && header->code == TCN_SELCHANGE) {
                const int kIndex = static_cast<int>(::SendMessageW(state->tab, TCM_GETCURSEL, 0, 0));
                activateIndex(*state, kIndex, false);
                return 0;
            }
        }
        break;
    case kMsgMaterialize:
        if (state) {
            const int kIndex = static_cast<int>(wParam);
            if (kIndex >= 0 && kIndex < static_cast<int>(state->slots.size())) {
                state->slots[static_cast<std::size_t>(kIndex)].materializePosted = false;
                materialize(*state, kIndex);
            }
        }
        return 0;
    case WM_CTLCOLORSTATIC: {
        HDC dc = reinterpret_cast<HDC>(wParam);
        ::SetBkMode(dc, TRANSPARENT);
        ::SetTextColor(dc, appTheme().textColor);
        return reinterpret_cast<LRESULT>(appTheme().windowBrush());
    }
    case WM_NCDESTROY:
        delete state;
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
        return 0;
    default:
        break;
    }
    return ::DefWindowProcW(hwnd, message, wParam, lParam);
}

bool registerWorkspaceClass() {
    static bool registered = false;
    if (registered) {
        return true;
    }
    WNDCLASSW windowClass{};
    windowClass.lpfnWndProc = workspaceProc;
    windowClass.hInstance = ::GetModuleHandleW(nullptr);
    windowClass.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
    windowClass.hbrBackground = appTheme().windowBrush();
    windowClass.lpszClassName = kWorkspaceHostClass;
    registered = ::RegisterClassW(&windowClass) != 0 || ::GetLastError() == ERROR_CLASS_ALREADY_EXISTS;
    return registered;
}

} // namespace

HWND createWorkspaceHost(
    HWND parent,
    const RECT& bounds,
    std::vector<WorkspaceTabDescriptor> tabs,
    WorkspaceOptions options) {
    if (!parent || tabs.empty() || !registerWorkspaceClass()) {
        return nullptr;
    }
    auto* state = new WorkspaceState();
    state->options = std::move(options);
    state->slots.reserve(tabs.size());
    for (WorkspaceTabDescriptor& descriptor : tabs) {
        state->slots.push_back({ std::move(descriptor) });
    }
    HWND workspace = ::CreateWindowExW(
        0,
        kWorkspaceHostClass,
        L"Workspace",
        WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN | WS_CLIPSIBLINGS,
        bounds.left,
        bounds.top,
        width(bounds),
        height(bounds),
        parent,
        nullptr,
        ::GetModuleHandleW(nullptr),
        state);
    if (!workspace) {
        delete state;
    }
    return workspace;
}

HWND workspaceHostPage(HWND workspace, const int tabId, const bool materializePage) {
    WorkspaceState* state = stateFromWindow(workspace);
    if (!state) {
        return nullptr;
    }
    const int kIndex = indexForId(*state, tabId);
    if (kIndex < 0) {
        return nullptr;
    }
    return materializePage ? materialize(*state, kIndex) : state->slots[static_cast<std::size_t>(kIndex)].page;
}

int workspaceHostActiveTabId(HWND workspace) {
    WorkspaceState* state = stateFromWindow(workspace);
    if (!state || state->activeIndex < 0 || state->activeIndex >= static_cast<int>(state->slots.size())) {
        return 0;
    }
    return state->slots[static_cast<std::size_t>(state->activeIndex)].descriptor.id;
}

bool activateWorkspaceHostTab(HWND workspace, const int tabId, const bool materializePage) {
    WorkspaceState* state = stateFromWindow(workspace);
    if (!state) {
        return false;
    }
    const int kIndex = indexForId(*state, tabId);
    if (kIndex < 0) {
        return false;
    }
    activateIndex(*state, kIndex, materialize);
    return !materialize || state->slots[static_cast<std::size_t>(kIndex)].materialized;
}

} // namespace Ksword::Ui

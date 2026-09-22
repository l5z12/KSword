#include "FilterBar.h"

#include "Controls.h"
#include "Theme.h"
#include "VirtualListView.h"

#include <algorithm>
#include <commctrl.h>
#include <cwctype>
#include <string>

namespace ksword::ui {
namespace {

constexpr wchar_t kFilterBarClass[] = L"KswordARKLight.FilterBar";
constexpr int kFilterEditId = 1;
constexpr int kFilterClearId = 2;
constexpr int kFilterRegexId = 3;
constexpr UINT_PTR kFilterDebounceTimer = 1;
constexpr UINT kFilterDebounceMilliseconds = 200;

struct FilterBarState final {
    int notificationId = 0;
    HWND edit = nullptr;
    HWND clearButton = nullptr;
    HWND regexButton = nullptr;
    bool notifyParent = true;
};

std::wstring trim(std::wstring value) {
    const auto kBegin = std::find_if_not(value.begin(), value.end(), [](const wchar_t ch) { return iswspace(ch) != 0; });
    const auto kEnd = std::find_if_not(value.rbegin(), value.rend(), [](const wchar_t ch) { return iswspace(ch) != 0; }).base();
    return kBegin >= kEnd ? std::wstring{} : std::wstring(kBegin, kEnd);
}

void notifyChanged(HWND hwnd, const FilterBarState& state) {
    HWND parent = ::GetParent(hwnd);
    if (state.notifyParent && parent && state.notificationId != 0) {
        ::SendMessageW(parent, WM_COMMAND, MAKEWPARAM(state.notificationId, EN_CHANGE), reinterpret_cast<LPARAM>(hwnd));
    }
}

// refreshRegexIndicator keeps the toggle honest about whether the pattern is
// actually in effect. A malformed pattern silently degrades to substring
// matching, so without this the box would look like it is filtering by regex
// while doing something else.
void refreshRegexIndicator(const FilterBarState& state) {
    if (!state.regexButton) {
        return;
    }
    const bool kEnabled = ::SendMessageW(state.regexButton, BM_GETCHECK, 0, 0) == BST_CHECKED;
    if (!kEnabled) {
        ::SetWindowTextW(state.regexButton, L".*");
        return;
    }
    const int kLength = ::GetWindowTextLengthW(state.edit);
    std::wstring query(static_cast<std::size_t>(std::max(0, kLength)) + 1U, L'\0');
    if (kLength > 0) {
        ::GetWindowTextW(state.edit, query.data(), kLength + 1);
    }
    query.resize(static_cast<std::size_t>(std::max(0, kLength)));
    const std::wstring kTrimmed = trim(std::move(query));
    const bool kUsable = kTrimmed.empty() || VirtualListView::isValidFilterRegex(kTrimmed);
    ::SetWindowTextW(state.regexButton, kUsable ? L".*" : L".*!");
}

void layout(HWND hwnd, FilterBarState& state) {
    RECT rect{};
    ::GetClientRect(hwnd, &rect);
    const int kClientWidth = static_cast<int>(rect.right - rect.left);
    const int kHeight = std::max(1, static_cast<int>(rect.bottom - rect.top));
    const int kClearWidth = std::min(30, std::max(22, kHeight));
    const int kRegexWidth = kClearWidth;
    if (state.edit) {
        ::MoveWindow(state.edit, 0, 0, std::max(1, kClientWidth - kClearWidth - kRegexWidth), kHeight, TRUE);
    }
    if (state.regexButton) {
        ::MoveWindow(state.regexButton, std::max(0, kClientWidth - kClearWidth - kRegexWidth), 0, kRegexWidth, kHeight, TRUE);
    }
    if (state.clearButton) {
        ::MoveWindow(state.clearButton, std::max(0, kClientWidth - kClearWidth), 0, kClearWidth, kHeight, TRUE);
    }
}

LRESULT CALLBACK filterBarProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam) {
    auto* state = reinterpret_cast<FilterBarState*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    switch (message) {
    case WM_NCCREATE: {
        const auto* create = reinterpret_cast<const CREATESTRUCTW*>(lParam);
        state = static_cast<FilterBarState*>(create->lpCreateParams);
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(state));
        return TRUE;
    }
    case WM_CREATE:
        if (state) {
            state->edit = ::CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
                0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kFilterEditId)), ::GetModuleHandleW(nullptr), nullptr);
            state->regexButton = ::CreateWindowExW(0, L"BUTTON", L".*",
                WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX | BS_PUSHLIKE,
                0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kFilterRegexId)), ::GetModuleHandleW(nullptr), nullptr);
            state->clearButton = ::CreateWindowExW(0, L"BUTTON", L"×", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
                0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kFilterClearId)), ::GetModuleHandleW(nullptr), nullptr);
            ::SendMessageW(state->edit, WM_SETFONT, reinterpret_cast<WPARAM>(systemUiFont()), TRUE);
            ::SendMessageW(state->regexButton, WM_SETFONT, reinterpret_cast<WPARAM>(systemUiFont()), TRUE);
            ::SendMessageW(state->clearButton, WM_SETFONT, reinterpret_cast<WPARAM>(systemUiFont()), TRUE);
        }
        return 0;
    case WM_SIZE:
        if (state) {
            layout(hwnd, *state);
        }
        return 0;
    case WM_COMMAND:
        if (!state) {
            break;
        }
        if (LOWORD(wParam) == kFilterEditId && HIWORD(wParam) == EN_CHANGE) {
            refreshRegexIndicator(*state);
            ::KillTimer(hwnd, kFilterDebounceTimer);
            ::SetTimer(hwnd, kFilterDebounceTimer, kFilterDebounceMilliseconds, nullptr);
            return 0;
        }
        if (LOWORD(wParam) == kFilterRegexId && HIWORD(wParam) == BN_CLICKED) {
            // Switching mode re-filters immediately: the text has not changed,
            // so nothing else would trigger a refresh and the table would keep
            // showing the previous mode's result.
            refreshRegexIndicator(*state);
            ::KillTimer(hwnd, kFilterDebounceTimer);
            notifyChanged(hwnd, *state);
            ::SetFocus(state->edit);
            return 0;
        }
        if (LOWORD(wParam) == kFilterClearId && HIWORD(wParam) == BN_CLICKED) {
            ::SetWindowTextW(state->edit, L"");
            ::SetFocus(state->edit);
            return 0;
        }
        break;
    case WM_TIMER:
        if (state && wParam == kFilterDebounceTimer) {
            ::KillTimer(hwnd, kFilterDebounceTimer);
            notifyChanged(hwnd, *state);
            return 0;
        }
        break;
    case WM_ERASEBKGND:
        return 1;
    case WM_PAINT: {
        PAINTSTRUCT paint{};
        HDC dc = ::BeginPaint(hwnd, &paint);
        RECT rect{};
        ::GetClientRect(hwnd, &rect);
        ::FillRect(dc, &rect, appTheme().panelBrush());
        ::EndPaint(hwnd, &paint);
        return 0;
    }
    case WM_NCDESTROY:
        ::KillTimer(hwnd, kFilterDebounceTimer);
        delete state;
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
        return 0;
    default:
        break;
    }
    return ::DefWindowProcW(hwnd, message, wParam, lParam);
}

bool ensureFilterBarClass() {
    static bool registered = false;
    if (registered) {
        return true;
    }
    WNDCLASSW windowClass{};
    windowClass.lpfnWndProc = filterBarProc;
    windowClass.hInstance = ::GetModuleHandleW(nullptr);
    windowClass.hCursor = ::LoadCursorW(nullptr, IDC_IBEAM);
    windowClass.hbrBackground = appTheme().panelBrush();
    windowClass.lpszClassName = kFilterBarClass;
    registered = ::RegisterClassW(&windowClass) != 0 || ::GetLastError() == ERROR_CLASS_ALREADY_EXISTS;
    return registered;
}

} // namespace

HWND createFilterBar(HWND parent, const int id, const std::wstring& cueText, const int x, const int y, const int width, const int height) {
    if (!parent || !ensureFilterBarClass()) {
        return nullptr;
    }
    auto* state = new FilterBarState{};
    state->notificationId = id;
    HWND filterBar = ::CreateWindowExW(0, kFilterBarClass, L"", WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS,
        x, y, width, height, parent, reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), ::GetModuleHandleW(nullptr), state);
    if (!filterBar) {
        delete state;
        return nullptr;
    }
    if (state->edit) {
        ::SendMessageW(state->edit, EM_SETCUEBANNER, TRUE, reinterpret_cast<LPARAM>(cueText.c_str()));
    }
    return filterBar;
}

std::wstring getFilterBarText(HWND filterBar) {
    auto* state = filterBar ? reinterpret_cast<FilterBarState*>(::GetWindowLongPtrW(filterBar, GWLP_USERDATA)) : nullptr;
    if (!state || !state->edit) {
        return {};
    }
    const int kLength = ::GetWindowTextLengthW(state->edit);
    std::wstring text(static_cast<std::size_t>(std::max(0, kLength)) + 1U, L'\0');
    if (kLength > 0) {
        ::GetWindowTextW(state->edit, text.data(), kLength + 1);
    }
    text.resize(static_cast<std::size_t>(std::max(0, kLength)));
    return trim(std::move(text));
}

void setFilterBarText(HWND filterBar, const std::wstring& text, const bool notifyParent) {
    auto* state = filterBar ? reinterpret_cast<FilterBarState*>(::GetWindowLongPtrW(filterBar, GWLP_USERDATA)) : nullptr;
    if (!state || !state->edit) {
        return;
    }
    state->notifyParent = notifyParent;
    ::SetWindowTextW(state->edit, text.c_str());
    ::KillTimer(filterBar, kFilterDebounceTimer);
    state->notifyParent = true;
    if (notifyParent) {
        ::KillTimer(filterBar, kFilterDebounceTimer);
        ::SetTimer(filterBar, kFilterDebounceTimer, kFilterDebounceMilliseconds, nullptr);
    }
}

bool getFilterBarRegexEnabled(HWND filterBar) {
    auto* state = filterBar ? reinterpret_cast<FilterBarState*>(::GetWindowLongPtrW(filterBar, GWLP_USERDATA)) : nullptr;
    if (!state || !state->regexButton) {
        return false;
    }
    return ::SendMessageW(state->regexButton, BM_GETCHECK, 0, 0) == BST_CHECKED;
}

void focusFilterBar(HWND filterBar) {
    auto* state = filterBar ? reinterpret_cast<FilterBarState*>(::GetWindowLongPtrW(filterBar, GWLP_USERDATA)) : nullptr;
    if (state && state->edit) {
        ::SetFocus(state->edit);
    }
}

} // namespace Ksword::Ui

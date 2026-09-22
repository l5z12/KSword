#include "TextFindSupport.h"

#include "Controls.h"
#include "ListViewUtil.h"
#include "Theme.h"

#include <algorithm>
#include <cstring>
#include <cwctype>
#include <iterator>
#include <regex>
#include <string>

#include <commctrl.h>

namespace ksword::ui {
namespace {

constexpr wchar_t kFindBarClass[] = L"KswordARKLight.TextFindBar";

// Subclass ids are arbitrary but must stay unique per control, since the target
// EDIT may already be subclassed by its owning feature page.
constexpr UINT_PTR kEditSubclassId = 0x4B535446;   // 'KSTF'
constexpr UINT_PTR kFieldSubclassId = 0x4B534646;  // 'KSFF'

constexpr int kIdFindEdit = 1;
constexpr int kIdFindPrevious = 2;
constexpr int kIdFindNext = 3;
constexpr int kIdMatchCase = 4;
constexpr int kIdUseRegex = 5;
constexpr int kIdReplaceEdit = 6;
constexpr int kIdReplaceOne = 7;
constexpr int kIdReplaceAll = 8;
constexpr int kIdClose = 9;
constexpr int kIdStatus = 10;

constexpr int kBarMargin = 4;
constexpr int kRowHeight = 24;
constexpr int kRowGap = 4;
constexpr int kQueryWidth = 176;
constexpr int kToggleWidth = 30;
constexpr int kStepWidth = 30;
constexpr int kCloseWidth = 26;
constexpr int kStatusWidth = 128;
constexpr int kReplaceOneWidth = 60;
constexpr int kReplaceAllWidth = 78;

// kMatchCountCeiling caps the "how many matches" scan. The count is a comfort
// figure, not a result the user acts on, and an unbounded scan over a multi-
// megabyte log would stall the UI thread for something nobody waits for.
constexpr int kMatchCountCeiling = 9999;

// MatchRange is one hit expressed as a half-open character range over the
// control text. Character offsets line up with EM_SETSEL because the text is
// read straight from the control, CRLF pairs included.
struct MatchRange final {
    std::size_t begin = 0;
    std::size_t end = 0;
};

struct FindSupportState final {
    HWND edit = nullptr;
    HWND bar = nullptr;
    HWND findEdit = nullptr;
    HWND replaceEdit = nullptr;
    HWND matchCaseToggle = nullptr;
    HWND regexToggle = nullptr;
    HWND statusLabel = nullptr;
    bool readOnly = true;
};

std::wstring readControlText(HWND control) {
    if (!control) {
        return {};
    }
    const int kLength = ::GetWindowTextLengthW(control);
    if (kLength <= 0) {
        return {};
    }
    std::wstring text(static_cast<std::size_t>(kLength) + 1U, L'\0');
    const int kCopied = ::GetWindowTextW(control, text.data(), kLength + 1);
    text.resize(static_cast<std::size_t>((std::max)(0, kCopied)));
    return text;
}

bool isControlReadOnly(HWND control) {
    const LONG_PTR kStyle = ::GetWindowLongPtrW(control, GWL_STYLE);
    return (kStyle & ES_READONLY) != 0;
}

// charactersEqual is the comparison shared by the forward and backward literal
// searches so both directions agree on what "same text" means.
bool charactersEqual(const wchar_t left, const wchar_t right, const bool matchCase) {
    if (matchCase) {
        return left == right;
    }
    return std::towlower(left) == std::towlower(right);
}

std::regex_constants::syntax_option_type regexFlags(const bool matchCase) {
    auto flags = std::regex_constants::ECMAScript;
    if (!matchCase) {
        flags |= std::regex_constants::icase;
    }
    return flags;
}

// compileRegex reports failure instead of letting std::regex_error escape.
// A half-typed pattern is the normal state of an incremental search box, so an
// invalid pattern is an expected input, not an error condition.
bool compileRegex(const std::wstring& pattern, const bool matchCase, std::wregex& regexOut) {
    if (pattern.empty()) {
        return false;
    }
    try {
        regexOut.assign(pattern, regexFlags(matchCase));
    } catch (const std::regex_error&) {
        return false;
    }
    return true;
}

bool findLiteralForward(
    const std::wstring& haystack,
    const std::wstring& needle,
    const std::size_t from,
    const bool matchCase,
    MatchRange& matchOut) {
    if (needle.empty() || needle.size() > haystack.size()) {
        return false;
    }
    const std::size_t kStart = (std::min)(from, haystack.size());
    const auto kFound = std::search(
        haystack.begin() + static_cast<std::ptrdiff_t>(kStart), haystack.end(),
        needle.begin(), needle.end(),
        [matchCase](const wchar_t left, const wchar_t right) { return charactersEqual(left, right, matchCase); });
    if (kFound == haystack.end()) {
        return false;
    }
    matchOut.begin = static_cast<std::size_t>(std::distance(haystack.begin(), kFound));
    matchOut.end = matchOut.begin + needle.size();
    return true;
}

bool findLiteralBackward(
    const std::wstring& haystack,
    const std::wstring& needle,
    const std::size_t before,
    const bool matchCase,
    MatchRange& matchOut) {
    if (needle.empty() || needle.size() > haystack.size()) {
        return false;
    }
    const std::size_t kLimit = (std::min)(before, haystack.size());
    if (kLimit < needle.size()) {
        return false;
    }
    const auto kFound = std::find_end(
        haystack.begin(), haystack.begin() + static_cast<std::ptrdiff_t>(kLimit),
        needle.begin(), needle.end(),
        [matchCase](const wchar_t left, const wchar_t right) { return charactersEqual(left, right, matchCase); });
    if (kFound == haystack.begin() + static_cast<std::ptrdiff_t>(kLimit)) {
        return false;
    }
    matchOut.begin = static_cast<std::size_t>(std::distance(haystack.begin(), kFound));
    matchOut.end = matchOut.begin + needle.size();
    return true;
}

bool findRegexForward(
    const std::wstring& haystack,
    const std::wregex& pattern,
    const std::size_t from,
    MatchRange& matchOut) {
    std::size_t start = (std::min)(from, haystack.size());
    // A pattern such as "a*" matches the empty string everywhere. Stepping past
    // each empty hit keeps the search moving instead of pinning it in place.
    while (start <= haystack.size()) {
        std::wsmatch match;
        auto searchFlags = std::regex_constants::match_default;
        if (start > 0) {
            searchFlags |= std::regex_constants::match_prev_avail;
        }
        if (!std::regex_search(
                haystack.cbegin() + static_cast<std::ptrdiff_t>(start), haystack.cend(), match, pattern, searchFlags)) {
            return false;
        }
        const std::size_t kBegin = start + static_cast<std::size_t>(match.position(0));
        const std::size_t kLength = static_cast<std::size_t>(match.length(0));
        if (kLength > 0) {
            matchOut.begin = kBegin;
            matchOut.end = kBegin + kLength;
            return true;
        }
        start = kBegin + 1;
    }
    return false;
}

bool findRegexBackward(
    const std::wstring& haystack,
    const std::wregex& pattern,
    const std::size_t before,
    MatchRange& matchOut) {
    const std::size_t kLimit = (std::min)(before, haystack.size());
    bool found = false;
    for (auto iterator = std::wsregex_iterator(haystack.cbegin(), haystack.cend(), pattern);
         iterator != std::wsregex_iterator(); ++iterator) {
        const std::size_t kBegin = static_cast<std::size_t>(iterator->position(0));
        const std::size_t kLength = static_cast<std::size_t>(iterator->length(0));
        if (kLength == 0) {
            continue;
        }
        if (kBegin >= kLimit) {
            break;
        }
        matchOut.begin = kBegin;
        matchOut.end = kBegin + kLength;
        found = true;
    }
    return found;
}

int countMatches(
    const std::wstring& haystack,
    const std::wstring& needle,
    const bool matchCase,
    const bool useRegex,
    const std::wregex& compiled) {
    int count = 0;
    if (useRegex) {
        for (auto iterator = std::wsregex_iterator(haystack.cbegin(), haystack.cend(), compiled);
             iterator != std::wsregex_iterator() && count < kMatchCountCeiling; ++iterator) {
            if (iterator->length(0) > 0) {
                ++count;
            }
        }
        return count;
    }
    std::size_t cursor = 0;
    MatchRange match{};
    while (count < kMatchCountCeiling && findLiteralForward(haystack, needle, cursor, matchCase, match)) {
        ++count;
        cursor = match.end;
    }
    return count;
}

// normalizeBackreferences accepts the "\1" spelling for capture groups next to
// the "$1" that std::regex formatting expects, because both spellings are in
// common use and getting the wrong one silently inserts a literal instead.
std::wstring normalizeBackreferences(const std::wstring& replacement) {
    std::wstring normalized;
    normalized.reserve(replacement.size());
    for (std::size_t index = 0; index < replacement.size(); ++index) {
        if (replacement[index] == L'\\' && index + 1 < replacement.size() &&
            replacement[index + 1] >= L'1' && replacement[index + 1] <= L'9') {
            normalized.push_back(L'$');
            normalized.push_back(replacement[index + 1]);
            ++index;
            continue;
        }
        normalized.push_back(replacement[index]);
    }
    return normalized;
}

void setBarStatus(const FindSupportState& state, const std::wstring& text) {
    if (state.statusLabel) {
        ::SetWindowTextW(state.statusLabel, text.c_str());
    }
}

bool toggleChecked(HWND toggle) {
    return toggle != nullptr && ::SendMessageW(toggle, BM_GETCHECK, 0, 0) == BST_CHECKED;
}

void selectMatchInEdit(HWND edit, const MatchRange& match) {
    ::SendMessageW(edit, EM_SETSEL, static_cast<WPARAM>(match.begin), static_cast<LPARAM>(match.end));
    ::SendMessageW(edit, EM_SCROLLCARET, 0, 0);
}

// RunFind performs one search step and reports what happened on the bar. The
// search wraps: reaching the end restarts from the top, which is what every
// editor does and what makes repeated F3 usable.
void runFind(FindSupportState& state, const bool backward, const bool fromSelectionStart) {
    if (!state.edit) {
        return;
    }
    const std::wstring kQuery = readControlText(state.findEdit);
    if (kQuery.empty()) {
        setBarStatus(state, L"输入要查找的内容");
        return;
    }
    const std::wstring kHaystack = readControlText(state.edit);
    if (kHaystack.empty()) {
        setBarStatus(state, L"此处没有可查找的文本");
        return;
    }

    const bool kMatchCase = toggleChecked(state.matchCaseToggle);
    const bool kUseRegex = toggleChecked(state.regexToggle);
    std::wregex compiled;
    if (kUseRegex && !compileRegex(kQuery, kMatchCase, compiled)) {
        setBarStatus(state, L"正则表达式无效");
        return;
    }

    DWORD selectionBegin = 0;
    DWORD selectionEnd = 0;
    ::SendMessageW(state.edit, EM_GETSEL, reinterpret_cast<WPARAM>(&selectionBegin), reinterpret_cast<LPARAM>(&selectionEnd));
    // Searching forward starts past the current selection so the same hit is not
    // returned twice; searching backward starts at its head for the same reason.
    const std::size_t kForwardStart = fromSelectionStart
        ? static_cast<std::size_t>(selectionBegin)
        : static_cast<std::size_t>(selectionEnd);
    const std::size_t kBackwardLimit = static_cast<std::size_t>(selectionBegin);

    MatchRange match{};
    bool found = false;
    bool wrapped = false;
    if (backward) {
        found = kUseRegex
            ? findRegexBackward(kHaystack, compiled, kBackwardLimit, match)
            : findLiteralBackward(kHaystack, kQuery, kBackwardLimit, kMatchCase, match);
        if (!found) {
            wrapped = true;
            found = kUseRegex
                ? findRegexBackward(kHaystack, compiled, kHaystack.size(), match)
                : findLiteralBackward(kHaystack, kQuery, kHaystack.size(), kMatchCase, match);
        }
    } else {
        found = kUseRegex
            ? findRegexForward(kHaystack, compiled, kForwardStart, match)
            : findLiteralForward(kHaystack, kQuery, kForwardStart, kMatchCase, match);
        if (!found) {
            wrapped = true;
            found = kUseRegex
                ? findRegexForward(kHaystack, compiled, 0, match)
                : findLiteralForward(kHaystack, kQuery, 0, kMatchCase, match);
        }
    }

    if (!found) {
        setBarStatus(state, L"未找到匹配项");
        return;
    }

    selectMatchInEdit(state.edit, match);
    const int kTotal = countMatches(kHaystack, kQuery, kMatchCase, kUseRegex, compiled);
    std::wstring status = kTotal >= kMatchCountCeiling
        ? std::wstring(L"共 ") + std::to_wstring(kMatchCountCeiling) + L"+ 项"
        : std::wstring(L"共 ") + std::to_wstring(kTotal) + L" 项";
    if (wrapped) {
        status += L"（已回到开头）";
    }
    setBarStatus(state, status);
}

// runReplaceOne replaces the current selection when it is already a match, then
// advances. Replacing without that check would let the button overwrite whatever
// the user happened to have selected.
void runReplaceOne(FindSupportState& state) {
    if (!state.edit || state.readOnly || !state.replaceEdit) {
        return;
    }
    const std::wstring kQuery = readControlText(state.findEdit);
    if (kQuery.empty()) {
        setBarStatus(state, L"输入要查找的内容");
        return;
    }
    const bool kMatchCase = toggleChecked(state.matchCaseToggle);
    const bool kUseRegex = toggleChecked(state.regexToggle);
    std::wregex compiled;
    if (kUseRegex && !compileRegex(kQuery, kMatchCase, compiled)) {
        setBarStatus(state, L"正则表达式无效");
        return;
    }

    DWORD selectionBegin = 0;
    DWORD selectionEnd = 0;
    ::SendMessageW(state.edit, EM_GETSEL, reinterpret_cast<WPARAM>(&selectionBegin), reinterpret_cast<LPARAM>(&selectionEnd));
    const std::wstring kHaystack = readControlText(state.edit);
    const std::wstring kReplacement = readControlText(state.replaceEdit);

    bool selectionIsMatch = false;
    std::wstring replacementText = kReplacement;
    if (selectionEnd > selectionBegin && selectionEnd <= kHaystack.size()) {
        const std::wstring kSelected = kHaystack.substr(selectionBegin, selectionEnd - selectionBegin);
        if (kUseRegex) {
            std::wsmatch match;
            if (std::regex_match(kSelected, match, compiled)) {
                selectionIsMatch = true;
                replacementText = match.format(normalizeBackreferences(kReplacement));
            }
        } else if (kSelected.size() == kQuery.size() &&
                   std::equal(kSelected.begin(), kSelected.end(), kQuery.begin(),
                       [kMatchCase](const wchar_t left, const wchar_t right) {
                           return charactersEqual(left, right, kMatchCase);
                       })) {
            selectionIsMatch = true;
        }
    }

    if (!selectionIsMatch) {
        // Nothing suitable is selected yet, so this click only locates the next
        // match. A second click then replaces it.
        runFind(state, false, true);
        return;
    }

    ::SendMessageW(state.edit, EM_REPLACESEL, TRUE, reinterpret_cast<LPARAM>(replacementText.c_str()));
    runFind(state, false, false);
}

void runReplaceAll(FindSupportState& state) {
    if (!state.edit || state.readOnly || !state.replaceEdit) {
        return;
    }
    const std::wstring kQuery = readControlText(state.findEdit);
    if (kQuery.empty()) {
        setBarStatus(state, L"输入要查找的内容");
        return;
    }
    const std::wstring kHaystack = readControlText(state.edit);
    if (kHaystack.empty()) {
        setBarStatus(state, L"此处没有可替换的文本");
        return;
    }
    const bool kMatchCase = toggleChecked(state.matchCaseToggle);
    const bool kUseRegex = toggleChecked(state.regexToggle);
    const std::wstring kReplacement = readControlText(state.replaceEdit);

    std::wstring rewritten;
    int replaced = 0;
    if (kUseRegex) {
        std::wregex compiled;
        if (!compileRegex(kQuery, kMatchCase, compiled)) {
            setBarStatus(state, L"正则表达式无效");
            return;
        }
        const std::wstring kFormatted = normalizeBackreferences(kReplacement);
        rewritten.reserve(kHaystack.size());
        std::size_t cursor = 0;
        for (auto iterator = std::wsregex_iterator(kHaystack.cbegin(), kHaystack.cend(), compiled);
             iterator != std::wsregex_iterator(); ++iterator) {
            const std::size_t kBegin = static_cast<std::size_t>(iterator->position(0));
            const std::size_t kLength = static_cast<std::size_t>(iterator->length(0));
            if (kLength == 0 || kBegin < cursor) {
                continue;
            }
            rewritten.append(kHaystack, cursor, kBegin - cursor);
            rewritten.append(iterator->format(kFormatted));
            cursor = kBegin + kLength;
            ++replaced;
        }
        rewritten.append(kHaystack, cursor, std::wstring::npos);
    } else {
        rewritten.reserve(kHaystack.size());
        std::size_t cursor = 0;
        MatchRange match{};
        while (findLiteralForward(kHaystack, kQuery, cursor, kMatchCase, match)) {
            rewritten.append(kHaystack, cursor, match.begin - cursor);
            rewritten.append(kReplacement);
            cursor = match.end;
            ++replaced;
        }
        rewritten.append(kHaystack, cursor, std::wstring::npos);
    }

    if (replaced == 0) {
        setBarStatus(state, L"未找到匹配项");
        return;
    }

    // The whole rewrite goes in as a single EM_REPLACESEL over a select-all, so
    // it lands as one undo step and one repaint instead of thousands.
    ScopedWindowRedrawLock redrawLock(state.edit);
    ::SendMessageW(state.edit, EM_SETSEL, 0, -1);
    ::SendMessageW(state.edit, EM_REPLACESEL, TRUE, reinterpret_cast<LPARAM>(rewritten.c_str()));
    ::SendMessageW(state.edit, EM_SETSEL, 0, 0);
    ::SendMessageW(state.edit, EM_SCROLLCARET, 0, 0);
    setBarStatus(state, std::wstring(L"已替换 ") + std::to_wstring(replaced) + L" 处");
}

void layoutFindBar(const FindSupportState& state) {
    if (!state.bar) {
        return;
    }
    RECT barRect{};
    ::GetClientRect(state.bar, &barRect);
    const int kBarWidth = static_cast<int>(barRect.right - barRect.left);
    const int kContentWidth = (std::max)(0, kBarWidth - kBarMargin * 2);

    int cursorX = kBarMargin;
    const int kFirstRowY = kBarMargin;
    const int kQueryWidthValue = (std::max)(60, (std::min)(kQueryWidth,
        kContentWidth - (kToggleWidth * 2 + kStepWidth * 2 + kCloseWidth + kStatusWidth)));

    ::MoveWindow(state.findEdit, cursorX, kFirstRowY, kQueryWidthValue, kRowHeight, TRUE);
    cursorX += kQueryWidthValue + 2;
    ::MoveWindow(state.matchCaseToggle, cursorX, kFirstRowY, kToggleWidth, kRowHeight, TRUE);
    cursorX += kToggleWidth + 2;
    ::MoveWindow(state.regexToggle, cursorX, kFirstRowY, kToggleWidth, kRowHeight, TRUE);
    cursorX += kToggleWidth + 2;

    HWND previousButton = ::GetDlgItem(state.bar, kIdFindPrevious);
    HWND nextButton = ::GetDlgItem(state.bar, kIdFindNext);
    HWND closeButton = ::GetDlgItem(state.bar, kIdClose);
    ::MoveWindow(previousButton, cursorX, kFirstRowY, kStepWidth, kRowHeight, TRUE);
    cursorX += kStepWidth + 2;
    ::MoveWindow(nextButton, cursorX, kFirstRowY, kStepWidth, kRowHeight, TRUE);
    cursorX += kStepWidth + 2;
    ::MoveWindow(closeButton, cursorX, kFirstRowY, kCloseWidth, kRowHeight, TRUE);
    cursorX += kCloseWidth + 4;
    const int kStatusWidthValue = (std::max)(0, kBarWidth - kBarMargin - cursorX);
    ::MoveWindow(state.statusLabel, cursorX, kFirstRowY + 4, kStatusWidthValue, kRowHeight - 4, TRUE);

    if (!state.readOnly && state.replaceEdit) {
        const int kSecondRowY = kFirstRowY + kRowHeight + kRowGap;
        ::MoveWindow(state.replaceEdit, kBarMargin, kSecondRowY, kQueryWidthValue, kRowHeight, TRUE);
        ::MoveWindow(::GetDlgItem(state.bar, kIdReplaceOne),
            kBarMargin + kQueryWidthValue + 2, kSecondRowY, kReplaceOneWidth, kRowHeight, TRUE);
        ::MoveWindow(::GetDlgItem(state.bar, kIdReplaceAll),
            kBarMargin + kQueryWidthValue + 2 + kReplaceOneWidth + 2, kSecondRowY, kReplaceAllWidth, kRowHeight, TRUE);
    }
}

// positionFindBar parks the bar in the top-right corner of the text control. It
// is a sibling of that control, not a child, because a child window inside an
// EDIT scrolls with the text and gets painted over by it.
void positionFindBar(const FindSupportState& state) {
    if (!state.bar || !state.edit) {
        return;
    }
    HWND parent = ::GetParent(state.edit);
    if (!parent) {
        return;
    }
    RECT editRect{};
    ::GetWindowRect(state.edit, &editRect);
    POINT topLeft{ editRect.left, editRect.top };
    POINT bottomRight{ editRect.right, editRect.bottom };
    ::ScreenToClient(parent, &topLeft);
    ::ScreenToClient(parent, &bottomRight);

    const int kEditWidth = (std::max)(0, static_cast<int>(bottomRight.x - topLeft.x));
    const int kRows = state.readOnly ? 1 : 2;
    const int kBarHeight = kBarMargin * 2 + kRowHeight * kRows + kRowGap * (kRows - 1);
    const int kPreferredWidth =
        kBarMargin * 2 + kQueryWidth + kToggleWidth * 2 + kStepWidth * 2 + kCloseWidth + kStatusWidth + 16;
    const int kBarWidth = (std::min)(kPreferredWidth, (std::max)(160, kEditWidth - 4));

    ::SetWindowPos(
        state.bar,
        HWND_TOP,
        topLeft.x + (std::max)(0, kEditWidth - kBarWidth) - 2,
        topLeft.y + 2,
        kBarWidth,
        kBarHeight,
        SWP_NOACTIVATE);
    layoutFindBar(state);
}

void closeFindBar(FindSupportState& state) {
    if (state.bar && ::IsWindowVisible(state.bar)) {
        ::ShowWindow(state.bar, SW_HIDE);
    }
    if (state.edit) {
        ::SetFocus(state.edit);
    }
}

LRESULT CALLBACK findFieldSubclassProc(
    HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam, UINT_PTR subclassId, DWORD_PTR referenceData) {
    auto* state = reinterpret_cast<FindSupportState*>(referenceData);
    switch (message) {
    case WM_KEYDOWN:
        if (state && wParam == VK_RETURN) {
            const bool kBackward = (::GetKeyState(VK_SHIFT) & 0x8000) != 0;
            runFind(*state, kBackward, false);
            return 0;
        }
        if (state && wParam == VK_ESCAPE) {
            closeFindBar(*state);
            return 0;
        }
        break;
    case WM_CHAR:
        // Swallow the Enter and Esc characters so the single-line edit does not
        // emit the default beep after the key was already acted on above.
        if (wParam == VK_RETURN || wParam == VK_ESCAPE) {
            return 0;
        }
        break;
    case WM_NCDESTROY:
        ::RemoveWindowSubclass(hwnd, findFieldSubclassProc, subclassId);
        break;
    default:
        break;
    }
    return ::DefSubclassProc(hwnd, message, wParam, lParam);
}

LRESULT CALLBACK findBarProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam) {
    auto* state = reinterpret_cast<FindSupportState*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    switch (message) {
    case WM_NCCREATE: {
        const auto* create = reinterpret_cast<const CREATESTRUCTW*>(lParam);
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(create->lpCreateParams));
        return TRUE;
    }
    case WM_SIZE:
        if (state) {
            layoutFindBar(*state);
        }
        return 0;
    case WM_COMMAND:
        if (!state) {
            break;
        }
        switch (LOWORD(wParam)) {
        case kIdFindNext:
            runFind(*state, false, false);
            return 0;
        case kIdFindPrevious:
            runFind(*state, true, false);
            return 0;
        case kIdClose:
            closeFindBar(*state);
            return 0;
        case kIdReplaceOne:
            runReplaceOne(*state);
            return 0;
        case kIdReplaceAll:
            runReplaceAll(*state);
            return 0;
        case kIdMatchCase:
        case kIdUseRegex:
            if (HIWORD(wParam) == BN_CLICKED) {
                // Changing a mode invalidates whatever the status line last
                // reported, so it is cleared rather than left stale.
                setBarStatus(*state, L"");
            }
            return 0;
        default:
            break;
        }
        break;
    case WM_CTLCOLORSTATIC:
        ::SetBkMode(reinterpret_cast<HDC>(wParam), TRANSPARENT);
        ::SetTextColor(reinterpret_cast<HDC>(wParam), appTheme().mutedTextColor);
        return reinterpret_cast<LRESULT>(appTheme().panelBrush());
    case WM_ERASEBKGND:
        return 1;
    case WM_PAINT: {
        PAINTSTRUCT paint{};
        HDC dc = ::BeginPaint(hwnd, &paint);
        RECT rect{};
        ::GetClientRect(hwnd, &rect);
        paintPanel(dc, rect);
        ::EndPaint(hwnd, &paint);
        return 0;
    }
    case WM_NCDESTROY:
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
        return 0;
    default:
        break;
    }
    return ::DefWindowProcW(hwnd, message, wParam, lParam);
}

bool ensureFindBarClass() {
    static bool registered = false;
    if (registered) {
        return true;
    }
    WNDCLASSW windowClass{};
    windowClass.lpfnWndProc = findBarProc;
    windowClass.hInstance = ::GetModuleHandleW(nullptr);
    windowClass.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
    windowClass.hbrBackground = appTheme().panelBrush();
    windowClass.lpszClassName = kFindBarClass;
    registered = ::RegisterClassW(&windowClass) != 0 || ::GetLastError() == ERROR_CLASS_ALREADY_EXISTS;
    return registered;
}

HWND createBarButton(HWND parent, const int id, const wchar_t* text, const DWORD extraStyle) {
    HWND button = ::CreateWindowExW(
        0, L"BUTTON", text,
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | extraStyle,
        0, 0, 0, 0, parent,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), ::GetModuleHandleW(nullptr), nullptr);
    if (button) {
        ::SendMessageW(button, WM_SETFONT, reinterpret_cast<WPARAM>(systemUiFont()), TRUE);
    }
    return button;
}

HWND createBarEdit(HWND parent, const int id, const wchar_t* cueText) {
    HWND edit = ::CreateWindowExW(
        WS_EX_CLIENTEDGE, L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
        0, 0, 0, 0, parent,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), ::GetModuleHandleW(nullptr), nullptr);
    if (edit) {
        ::SendMessageW(edit, WM_SETFONT, reinterpret_cast<WPARAM>(systemUiFont()), TRUE);
        ::SendMessageW(edit, EM_SETCUEBANNER, TRUE, reinterpret_cast<LPARAM>(cueText));
    }
    return edit;
}

bool ensureFindBar(FindSupportState& state) {
    if (state.bar) {
        return true;
    }
    HWND parent = ::GetParent(state.edit);
    if (!parent || !ensureFindBarClass()) {
        return false;
    }
    state.bar = ::CreateWindowExW(
        0, kFindBarClass, L"",
        WS_CHILD | WS_CLIPSIBLINGS | WS_CLIPCHILDREN,
        0, 0, 10, 10, parent, nullptr, ::GetModuleHandleW(nullptr), &state);
    if (!state.bar) {
        return false;
    }

    state.findEdit = createBarEdit(state.bar, kIdFindEdit, L"查找");
    state.matchCaseToggle = createBarButton(state.bar, kIdMatchCase, L"Aa", BS_AUTOCHECKBOX | BS_PUSHLIKE);
    state.regexToggle = createBarButton(state.bar, kIdUseRegex, L".*", BS_AUTOCHECKBOX | BS_PUSHLIKE);
    createBarButton(state.bar, kIdFindPrevious, L"↑", BS_PUSHBUTTON);
    createBarButton(state.bar, kIdFindNext, L"↓", BS_PUSHBUTTON);
    createBarButton(state.bar, kIdClose, L"×", BS_PUSHBUTTON);
    state.statusLabel = ::CreateWindowExW(
        0, L"STATIC", L"",
        WS_CHILD | WS_VISIBLE | SS_LEFTNOWORDWRAP | SS_ENDELLIPSIS,
        0, 0, 0, 0, state.bar,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(kIdStatus)), ::GetModuleHandleW(nullptr), nullptr);
    if (state.statusLabel) {
        ::SendMessageW(state.statusLabel, WM_SETFONT, reinterpret_cast<WPARAM>(systemUiFont()), TRUE);
    }

    if (!state.readOnly) {
        state.replaceEdit = createBarEdit(state.bar, kIdReplaceEdit, L"替换为（正则可用 $1..$9）");
        createBarButton(state.bar, kIdReplaceOne, L"替换", BS_PUSHBUTTON);
        createBarButton(state.bar, kIdReplaceAll, L"全部替换", BS_PUSHBUTTON);
    }

    if (state.findEdit) {
        ::SetWindowSubclass(state.findEdit, findFieldSubclassProc, kFieldSubclassId, reinterpret_cast<DWORD_PTR>(&state));
    }
    if (state.replaceEdit) {
        ::SetWindowSubclass(state.replaceEdit, findFieldSubclassProc, kFieldSubclassId, reinterpret_cast<DWORD_PTR>(&state));
    }
    return true;
}

void openFindBar(FindSupportState& state, const bool focusReplacement) {
    if (!ensureFindBar(state)) {
        return;
    }
    // Whatever the user had selected is the most likely thing they want to look
    // for, so a single-line selection seeds the query field.
    DWORD selectionBegin = 0;
    DWORD selectionEnd = 0;
    ::SendMessageW(state.edit, EM_GETSEL, reinterpret_cast<WPARAM>(&selectionBegin), reinterpret_cast<LPARAM>(&selectionEnd));
    if (selectionEnd > selectionBegin) {
        const std::wstring kText = readControlText(state.edit);
        if (selectionEnd <= kText.size()) {
            const std::wstring kSelected = kText.substr(selectionBegin, selectionEnd - selectionBegin);
            if (!kSelected.empty() && kSelected.find(L'\n') == std::wstring::npos && kSelected.size() <= 256) {
                ::SetWindowTextW(state.findEdit, kSelected.c_str());
            }
        }
    }

    positionFindBar(state);
    ::ShowWindow(state.bar, SW_SHOWNOACTIVATE);
    ::SetWindowPos(state.bar, HWND_TOP, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
    HWND focusTarget = (focusReplacement && state.replaceEdit) ? state.replaceEdit : state.findEdit;
    ::SetFocus(focusTarget);
    ::SendMessageW(focusTarget, EM_SETSEL, 0, -1);
}

LRESULT CALLBACK textEditSubclassProc(
    HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam, UINT_PTR subclassId, DWORD_PTR referenceData) {
    auto* state = reinterpret_cast<FindSupportState*>(referenceData);
    switch (message) {
    case WM_KEYDOWN: {
        if (!state) {
            break;
        }
        const bool kControlHeld = (::GetKeyState(VK_CONTROL) & 0x8000) != 0;
        const bool kShiftHeld = (::GetKeyState(VK_SHIFT) & 0x8000) != 0;
        if (kControlHeld && (wParam == L'F' || wParam == L'f')) {
            openFindBar(*state, false);
            return 0;
        }
        if (kControlHeld && (wParam == L'H' || wParam == L'h') && !state->readOnly) {
            openFindBar(*state, true);
            return 0;
        }
        if (wParam == VK_F3) {
            // F3 works without opening the bar, which is what makes "search once,
            // then step through the file" possible without the bar in the way.
            if (!state->bar) {
                openFindBar(*state, false);
                return 0;
            }
            runFind(*state, kShiftHeld, false);
            return 0;
        }
        if (wParam == VK_ESCAPE && state->bar && ::IsWindowVisible(state->bar)) {
            closeFindBar(*state);
            return 0;
        }
        break;
    }
    case WM_WINDOWPOSCHANGED:
    case WM_SIZE:
        if (state && state->bar && ::IsWindowVisible(state->bar)) {
            positionFindBar(*state);
        }
        break;
    case WM_NCDESTROY:
        ::RemoveWindowSubclass(hwnd, textEditSubclassProc, subclassId);
        if (state) {
            // The bar is a sibling, so a parent teardown may already have taken
            // it down before this control's own destruction reaches here.
            if (state->bar && ::IsWindow(state->bar)) {
                ::DestroyWindow(state->bar);
            }
            delete state;
        }
        break;
    default:
        break;
    }
    return ::DefSubclassProc(hwnd, message, wParam, lParam);
}

BOOL CALLBACK attachToMultilineEditProc(HWND child, LPARAM /*parameter*/) {
    wchar_t className[64]{};
    if (::GetClassNameW(child, className, static_cast<int>(std::size(className))) > 0 &&
        ::_wcsicmp(className, L"EDIT") == 0) {
        const LONG_PTR kStyle = ::GetWindowLongPtrW(child, GWL_STYLE);
        if ((kStyle & ES_MULTILINE) != 0) {
            attachTextFindSupport(child);
        }
    }
    return TRUE;
}

} // namespace

void attachTextFindSupport(HWND multilineEdit) {
    if (!multilineEdit || !::IsWindow(multilineEdit)) {
        return;
    }
    DWORD_PTR existing = 0;
    if (::GetWindowSubclass(multilineEdit, textEditSubclassProc, kEditSubclassId, &existing)) {
        return;
    }

    auto* state = new FindSupportState{};
    state->edit = multilineEdit;
    state->readOnly = isControlReadOnly(multilineEdit);
    if (!::SetWindowSubclass(multilineEdit, textEditSubclassProc, kEditSubclassId, reinterpret_cast<DWORD_PTR>(state))) {
        delete state;
        return;
    }

    // Without WS_CLIPSIBLINGS the text control repaints straight over the bar
    // that floats on top of it, so the bar would flicker away on every scroll.
    const LONG_PTR kStyle = ::GetWindowLongPtrW(multilineEdit, GWL_STYLE);
    if ((kStyle & WS_CLIPSIBLINGS) == 0) {
        ::SetWindowLongPtrW(multilineEdit, GWL_STYLE, kStyle | WS_CLIPSIBLINGS);
        ::SetWindowPos(multilineEdit, nullptr, 0, 0, 0, 0,
            SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE | SWP_FRAMECHANGED);
    }
}

void openTextFindSupport(HWND multilineEdit) {
    if (!multilineEdit || !::IsWindow(multilineEdit)) {
        return;
    }
    DWORD_PTR reference = 0;
    if (!::GetWindowSubclass(multilineEdit, textEditSubclassProc, kEditSubclassId, &reference)) {
        attachTextFindSupport(multilineEdit);
        reference = 0;
        if (!::GetWindowSubclass(multilineEdit, textEditSubclassProc, kEditSubclassId, &reference)) {
            return;
        }
    }
    if (auto* state = reinterpret_cast<FindSupportState*>(reference)) {
        openFindBar(*state, false);
    }
}

void attachTextFindSupportRecursive(HWND root) {
    if (!root || !::IsWindow(root)) {
        return;
    }
    ::EnumChildWindows(root, attachToMultilineEditProc, 0);
}

} // namespace Ksword::Ui

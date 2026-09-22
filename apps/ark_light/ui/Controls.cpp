#include "Controls.h"

#include "Theme.h"

#include <commctrl.h>

namespace ksword::ui {
namespace {
HFONT gSystemUIFont = nullptr;

// createSystemUiFont queries the active Windows non-client message font. Input is
// none; processing asks SystemParametersInfoW for NONCLIENTMETRICS; output is a
// newly created HFONT or DEFAULT_GUI_FONT fallback if the API fails.
HFONT createSystemUiFont() {
    NONCLIENTMETRICSW metrics{};
    metrics.cbSize = sizeof(metrics);
    if (::SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, metrics.cbSize, &metrics, 0)) {
        HFONT font = ::CreateFontIndirectW(&metrics.lfMessageFont);
        if (font) {
            return font;
        }
    }
    return reinterpret_cast<HFONT>(::GetStockObject(DEFAULT_GUI_FONT));
}
} // namespace

HFONT systemUiFont() {
    if (!gSystemUIFont) {
        gSystemUIFont = createSystemUiFont();
    }
    return gSystemUIFont;
}

void refreshSystemUiFont() {
    if (gSystemUIFont && reinterpret_cast<HGDIOBJ>(gSystemUIFont) != ::GetStockObject(DEFAULT_GUI_FONT)) {
        ::DeleteObject(gSystemUIFont);
    }
    gSystemUIFont = nullptr;
}

bool registerControlClasses(HINSTANCE instance) {
    INITCOMMONCONTROLSEX icc{};
    icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_LISTVIEW_CLASSES | ICC_TREEVIEW_CLASSES | ICC_TAB_CLASSES | ICC_BAR_CLASSES;
    ::InitCommonControlsEx(&icc);
    (void)instance;
    return true;
}

HWND createText(HWND parent, int id, const std::wstring& text, int x, int y, int w, int h) {
    HWND hwnd = ::CreateWindowExW(0, L"STATIC", text.c_str(), WS_CHILD | WS_VISIBLE | SS_LEFTNOWORDWRAP,
        x, y, w, h, parent, reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), ::GetModuleHandleW(nullptr), nullptr);
    if (hwnd) {
        ::SendMessageW(hwnd, WM_SETFONT, reinterpret_cast<WPARAM>(systemUiFont()), TRUE);
    }
    return hwnd;
}

HWND createButton(HWND parent, int id, const std::wstring& text, int x, int y, int w, int h) {
    HWND hwnd = ::CreateWindowExW(0, L"BUTTON", text.c_str(), WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
        x, y, w, h, parent, reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), ::GetModuleHandleW(nullptr), nullptr);
    if (hwnd) {
        ::SendMessageW(hwnd, WM_SETFONT, reinterpret_cast<WPARAM>(systemUiFont()), TRUE);
    }
    return hwnd;
}

void setWindowFontRecursive(HWND root) {
    if (!root) {
        return;
    }
    ::SendMessageW(root, WM_SETFONT, reinterpret_cast<WPARAM>(systemUiFont()), TRUE);
    ::EnumChildWindows(root, [](HWND child, LPARAM) -> BOOL {
        ::SendMessageW(child, WM_SETFONT, reinterpret_cast<WPARAM>(systemUiFont()), TRUE);
        return TRUE;
    }, 0);
}

void paintPanel(HDC dc, const RECT& rect) {
    ::FillRect(dc, &rect, appTheme().panelBrush());
    HPEN pen = ::CreatePen(PS_SOLID, 1, appTheme().borderColor);
    HGDIOBJ oldPen = ::SelectObject(dc, pen);
    HGDIOBJ oldBrush = ::SelectObject(dc, ::GetStockObject(HOLLOW_BRUSH));
    ::Rectangle(dc, rect.left, rect.top, rect.right, rect.bottom);
    ::SelectObject(dc, oldBrush);
    ::SelectObject(dc, oldPen);
    ::DeleteObject(pen);
}

void drawTextLine(HDC dc, const std::wstring& text, RECT rect, COLORREF color, HFONT font, UINT format) {
    const int kOldMode = ::SetBkMode(dc, TRANSPARENT);
    const COLORREF kOldColor = ::SetTextColor(dc, color);
    HFONT selectedFont = font ? font : systemUiFont();
    HGDIOBJ oldFont = ::SelectObject(dc, reinterpret_cast<HGDIOBJ>(selectedFont));
    ::DrawTextW(dc, text.c_str(), static_cast<int>(text.size()), &rect, format | DT_END_ELLIPSIS);
    ::SelectObject(dc, oldFont);
    ::SetTextColor(dc, kOldColor);
    ::SetBkMode(dc, kOldMode);
}

} // namespace Ksword::Ui

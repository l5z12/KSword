#include "TabUtil.h"

#include "Controls.h"

namespace ksword::ui {

HWND createTabControl(HWND parent, int id, int x, int y, int width, int height, DWORD extraStyle) {
    // Standard TabControl creation only. No custom frame, no themed owner draw,
    // and no artificial page padding is added here.
    const DWORD kStyle = WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_CLIPSIBLINGS | extraStyle;
    HWND hwnd = ::CreateWindowExW(
        0,
        WC_TABCONTROLW,
        L"",
        kStyle,
        x,
        y,
        width,
        height,
        parent,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)),
        ::GetModuleHandleW(nullptr),
        nullptr);
    if (hwnd) {
        ::SendMessageW(hwnd, WM_SETFONT, reinterpret_cast<WPARAM>(systemUiFont()), TRUE);
    }
    return hwnd;
}

bool addTabPage(HWND tabControl, int index, const TabPage& page) {
    // Text and optional image are mapped directly to TCITEMW. The caller chooses
    // page HWND ownership and visibility outside this helper.
    if (!tabControl || index < 0) {
        return false;
    }

    TCITEMW item{};
    item.mask = TCIF_TEXT | TCIF_PARAM;
    item.pszText = const_cast<LPWSTR>(page.title.c_str());
    item.lParam = page.itemData;
    if (page.image >= 0) {
        item.mask |= TCIF_IMAGE;
        item.iImage = page.image;
    }
    return TabCtrl_InsertItem(tabControl, index, &item) >= 0;
}

bool addTabPages(HWND tabControl, const std::vector<TabPage>& pages) {
    // Pages are appended at the current end so callers can build tab lists in a
    // natural vector order.
    if (!tabControl) {
        return false;
    }

    bool allOk = true;
    int index = TabCtrl_GetItemCount(tabControl);
    for (const TabPage& page : pages) {
        allOk = addTabPage(tabControl, index, page) && allOk;
        ++index;
    }
    return allOk;
}

HIMAGELIST setTabImageList(HWND tabControl, HIMAGELIST imageList) {
    // Image list ownership stays with the caller. The returned old handle lets
    // feature code perform explicit cleanup when needed.
    if (!tabControl) {
        return nullptr;
    }
    return TabCtrl_SetImageList(tabControl, imageList);
}

RECT getTabDisplayRect(HWND tabControl) {
    // The display rectangle is useful when a page wants to position a child
    // window flush inside the control. No additional padding is applied.
    RECT rect{};
    if (!tabControl) {
        return rect;
    }
    ::GetClientRect(tabControl, &rect);
    TabCtrl_AdjustRect(tabControl, FALSE, &rect);
    return rect;
}

} // namespace Ksword::Ui

#pragma once

#include "../core/Win32Lean.h"

#include <commctrl.h>
#include <string>
#include <vector>

namespace ksword::ui {

// TabPage describes one tab label and optional payload. It owns no HWND and is
// only consumed by addTabPage(s).
struct TabPage {
    std::wstring title;      // Text shown on the tab header.
    LPARAM itemData = 0;     // Caller-defined payload stored in TCITEM.lParam.
    int image = -1;          // Optional image index, or -1 for no image.
};

// createTabControl creates a child WC_TABCONTROLW. Inputs are parent, id and
// geometry; processing applies system UI font; output is HWND or nullptr.
HWND createTabControl(HWND parent, int id, int x, int y, int width, int height, DWORD extraStyle = 0);

// addTabPage inserts one tab at index. Inputs are a TabControl HWND, index and
// descriptor; processing sends TCM_INSERTITEMW; output is true on success.
bool addTabPage(HWND tabControl, int index, const TabPage& page);

// addTabPages appends all pages in order. Inputs are a TabControl HWND and page
// descriptors; processing inserts each tab; output is true if all insertions ok.
bool addTabPages(HWND tabControl, const std::vector<TabPage>& pages);

// setTabImageList assigns the tab image list. Inputs are TabControl HWND and
// HIMAGELIST; processing sends TCM_SETIMAGELIST; output is previous list.
HIMAGELIST setTabImageList(HWND tabControl, HIMAGELIST imageList);

// getTabDisplayRect returns the page display area inside a tab control. Input is
// a TabControl HWND; processing adjusts the client rect; output is RECT.
RECT getTabDisplayRect(HWND tabControl);

} // namespace Ksword::Ui

#pragma once

#include "../core/Win32Lean.h"

#include <string>
#include <vector>

namespace ksword::ui {

// PopupMenuItem describes one popup menu entry. It maps directly to AppendMenuW
// and intentionally does not introduce a menu command framework.
struct PopupMenuItem {
    UINT id = 0;             // Command id returned by TrackPopupMenu.
    std::wstring text;       // Visible item text; ignored for separators.
    bool separator = false;  // true creates a separator.
    bool enabled = true;     // false creates a disabled item.
    bool checked = false;    // true adds MF_CHECKED.
};

// buildPopupMenu creates an HMENU from item descriptors. Inputs are descriptors;
// processing appends each item; output is an HMENU that caller must destroy.
HMENU buildPopupMenu(const std::vector<PopupMenuItem>& items);

// trackPopupMenuForCommand shows a popup and returns the selected command id.
// Inputs are owner, menu and screen point; processing uses TPM_RETURNCMD; output
// is command id or 0 when cancelled.
UINT trackPopupMenuForCommand(HWND owner, HMENU menu, POINT screenPoint, UINT extraFlags = 0);

// showPopupMenuForCommand builds, shows and destroys a popup menu in one call.
// Inputs are owner, screen point and item descriptors; output is selected id.
UINT showPopupMenuForCommand(HWND owner, POINT screenPoint, const std::vector<PopupMenuItem>& items, UINT extraFlags = 0);

} // namespace Ksword::Ui

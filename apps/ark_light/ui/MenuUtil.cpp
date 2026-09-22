#include "MenuUtil.h"

namespace ksword::ui {

HMENU buildPopupMenu(const std::vector<PopupMenuItem>& items) {
    // This helper only converts descriptors to a native HMENU. The caller keeps
    // ownership and can still modify the menu with raw Win32 APIs before showing.
    HMENU menu = ::CreatePopupMenu();
    if (!menu) {
        return nullptr;
    }

    for (const PopupMenuItem& item : items) {
        if (item.separator) {
            ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
            continue;
        }

        UINT flags = MF_STRING;
        if (!item.enabled) {
            flags |= MF_GRAYED;
        }
        if (item.checked) {
            flags |= MF_CHECKED;
        }
        ::AppendMenuW(menu, flags, item.id, item.text.c_str());
    }

    return menu;
}

UINT trackPopupMenuForCommand(HWND owner, HMENU menu, POINT screenPoint, UINT extraFlags) {
    // TrackPopupMenu returns zero on cancel. The helper does not translate the
    // command into callbacks so feature pages can keep their own command switch.
    if (!owner || !menu) {
        return 0;
    }
    return static_cast<UINT>(::TrackPopupMenu(
        menu,
        TPM_RETURNCMD | TPM_RIGHTBUTTON | extraFlags,
        screenPoint.x,
        screenPoint.y,
        0,
        owner,
        nullptr));
}

UINT showPopupMenuForCommand(HWND owner, POINT screenPoint, const std::vector<PopupMenuItem>& items, UINT extraFlags) {
    // Build/show/destroy is the common right-click path. The selected command id
    // is returned to the caller, while HMENU lifetime stays local to this helper.
    HMENU menu = buildPopupMenu(items);
    if (!menu) {
        return 0;
    }

    const UINT kCommand = trackPopupMenuForCommand(owner, menu, screenPoint, extraFlags);
    ::DestroyMenu(menu);
    return kCommand;
}

} // namespace Ksword::Ui

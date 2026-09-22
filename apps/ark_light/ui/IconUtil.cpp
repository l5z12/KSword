#include "IconUtil.h"

#include <shellapi.h>

namespace ksword::ui {

HIMAGELIST createIconImageList(int iconWidth, int iconHeight, int initialCount, int growCount) {
    // Image lists are used by ListView/TreeView/TabControl helpers. The caller
    // owns the returned HIMAGELIST and should destroy it with ImageList_Destroy.
    return ImageList_Create(
        iconWidth,
        iconHeight,
        ILC_COLOR32 | ILC_MASK,
        initialCount,
        growCount);
}

HICON loadResourceIcon(HINSTANCE instance, int resourceId, int width, int height) {
    // The icon is loaded as LR_SHARED=false so the caller may safely destroy the
    // returned handle after adding it to an image list.
    HINSTANCE module = instance ? instance : ::GetModuleHandleW(nullptr);
    return reinterpret_cast<HICON>(::LoadImageW(
        module,
        MAKEINTRESOURCEW(resourceId),
        IMAGE_ICON,
        width,
        height,
        0));
}

HICON loadFileIcon(const std::wstring& path, bool largeIcon) {
    // SHGetFileInfoW provides the system shell icon for feature rows without
    // introducing a custom icon framework. The caller owns psfi.hIcon.
    SHFILEINFOW info{};
    const UINT kFlags = SHGFI_ICON | (largeIcon ? SHGFI_LARGEICON : SHGFI_SMALLICON);
    const DWORD_PTR kResult = ::SHGetFileInfoW(path.c_str(), 0, &info, sizeof(info), kFlags);
    return kResult == 0 ? nullptr : info.hIcon;
}

int addIconToImageList(HIMAGELIST imageList, HICON icon, bool destroyIcon) {
    // ImageList_AddIcon copies icon pixels into the image list. destroyIcon
    // allows one-line use with loadFileIcon/loadResourceIcon results.
    if (!imageList || !icon) {
        if (destroyIcon) {
            destroyIconIfNeeded(icon);
        }
        return -1;
    }

    const int kIndex = ImageList_AddIcon(imageList, icon);
    if (destroyIcon) {
        destroyIconIfNeeded(icon);
    }
    return kIndex;
}

void destroyIconIfNeeded(HICON icon) {
    if (icon) {
        ::DestroyIcon(icon);
    }
}

} // namespace Ksword::Ui

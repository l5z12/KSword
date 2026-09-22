#pragma once

#include "../core/Win32Lean.h"

#include <commctrl.h>
#include <string>

namespace ksword::ui {

// createIconImageList creates a color image list for small control icons. Inputs
// are icon size, initial capacity and grow count; output is HIMAGELIST or null.
HIMAGELIST createIconImageList(int iconWidth = 16, int iconHeight = 16, int initialCount = 8, int growCount = 8);

// loadResourceIcon loads an icon from the module resources. Inputs are module,
// resource id and size; output is HICON or null. The caller owns the icon.
HICON loadResourceIcon(HINSTANCE instance, int resourceId, int width = 16, int height = 16);

// loadFileIcon extracts the shell icon for a path. Inputs are a filesystem path
// and large/small choice; output is HICON or null. The caller owns the icon.
HICON loadFileIcon(const std::wstring& path, bool largeIcon = false);

// addIconToImageList appends an icon and optionally destroys it afterwards.
// Inputs are image list and icon; output is the image index or -1 on failure.
int addIconToImageList(HIMAGELIST imageList, HICON icon, bool destroyIcon = false);

// destroyIconIfNeeded destroys a non-null icon. Input is HICON; no return.
void destroyIconIfNeeded(HICON icon);

} // namespace Ksword::Ui

#pragma once

#include "../core/Win32Lean.h"

#include <commctrl.h>
#include <string>

namespace ksword::ui {

// createTreeView creates a child WC_TREEVIEWW. Inputs are parent, id and
// geometry; processing applies the system UI font; output is HWND or nullptr.
HWND createTreeView(HWND parent, int id, int x, int y, int width, int height, DWORD extraStyle = 0);

// insertTreeItem inserts one tree node. Inputs are the target tree, parent item,
// insertion point, text, images and caller data; processing sends TVM_INSERTITEM;
// output is the new HTREEITEM or nullptr on failure.
HTREEITEM insertTreeItem(
    HWND treeView,
    HTREEITEM parent,
    HTREEITEM insertAfter,
    const std::wstring& text,
    LPARAM itemData = 0,
    int image = -1,
    int selectedImage = -1);

// clearTreeView removes every node. Input is a TreeView HWND; processing sends
// TVM_DELETEITEM with TVI_ROOT; no value is returned.
void clearTreeView(HWND treeView);

// setTreeViewImageList assigns a normal image list. Inputs are TreeView HWND and
// image list handle; processing sends TVM_SETIMAGELIST; output is previous list.
HIMAGELIST setTreeViewImageList(HWND treeView, HIMAGELIST imageList);

} // namespace Ksword::Ui

#pragma once

#include "../core/Win32Lean.h"

#include <functional>
#include <string>
#include <vector>

namespace ksword::ui {

using WorkspacePageFactory = std::function<HWND(HWND parent, const RECT& bounds)>;

struct WorkspaceTabDescriptor final {
    int id = 0;
    std::wstring title;
    std::wstring summary;
    WorkspacePageFactory createPage;
};

struct WorkspaceOptions final {
    int tabControlId = 0;
    int initialTabId = 0;
    int margin = 0;
    std::function<void(int tabId, HWND page)> pageActivated;
};

// createWorkspaceHost creates a retained Win32 tab workspace whose child pages
// are materialized only when selected. The module owns placeholders, failure
// retry, layout, state preservation and activation callbacks behind this small
// interface; callers only provide immutable descriptors and page factories.
HWND createWorkspaceHost(
    HWND parent,
    const RECT& bounds,
    std::vector<WorkspaceTabDescriptor> tabs,
    WorkspaceOptions options = {});

// workspaceHostPage returns a page by stable tab id. materialize=true performs
// synchronous creation when command routing needs the page immediately.
HWND workspaceHostPage(HWND workspace, int tabId, bool materialize = false);

int workspaceHostActiveTabId(HWND workspace);
bool activateWorkspaceHostTab(HWND workspace, int tabId, bool materialize = true);

} // namespace Ksword::Ui

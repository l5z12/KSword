#include "ProcessFeature.h"

#include "ProcessView.h"

namespace ksword::features::process {

HWND createProcessFeaturePage(HWND parent, const RECT& bounds) {
    // Input is the host HWND and desired child bounds. Processing is intentionally
    // thin: this facade preserves a stable integration symbol while ProcessView
    // owns child controls, enumeration, model binding, and menu interactions.
    // Return value is the child page HWND or null if the view cannot be created.
    return createProcessView(parent, bounds);
}

void resizeProcessFeaturePage(HWND page, const RECT& bounds) {
    // Input is an existing process feature page and a new host layout rectangle.
    // Processing delegates to ProcessView, which uses MoveWindow only; there is
    // no return value because invalid HWNDs are safely ignored.
    resizeProcessView(page, bounds);
}

void requestProcessFeatureRefresh(HWND page) {
    // page usage: The HWND for the process page saved in mainWindow; called asynchronously after driver state changes to refresh.
    // Handling: Forward to ProcessView to avoid mainWindow directly depending on page-specific message IDs.
    requestProcessViewRefresh(page);
}

bool requestProcessFeatureOpenDetails(HWND page, DWORD processId, ULONGLONG expectedCreationTime100ns) {
    return requestProcessViewOpenDetails(page, processId, expectedCreationTime100ns);
}

} // namespace Ksword::Features::Process

#include "HandleFeature.h"

#include "HandlePage.h"

namespace ksword::features::handle {

HWND createHandleFeaturePage(HWND parent, const RECT& bounds) {
    // Input is the host dock HWND and desired child rectangle. Processing stays
    // intentionally thin so later FeatureRegistry registration has one stable
    // symbol; HandlePage owns controls, refresh, filtering, and read-only detail
    // rendering. The return value is the created page HWND or nullptr.
    return HandlePage::create(parent, bounds);
}

void resizeHandleFeaturePage(HWND page, const RECT& bounds) {
    // Input is an already-created page HWND and a new rectangle. Processing uses
    // MoveWindow only; there is no return value because the host layout contract
    // does not need synchronous status.
    if (page) {
        ::MoveWindow(
            page,
            bounds.left,
            bounds.top,
            bounds.right - bounds.left,
            bounds.bottom - bounds.top,
            TRUE);
    }
}

bool requestHandleFeatureProcess(HWND page, DWORD processId) {
    return HandlePage::setProcessId(page, processId);
}

} // namespace Ksword::Features::Handle

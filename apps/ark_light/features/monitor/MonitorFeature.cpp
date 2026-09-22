#include "MonitorFeature.h"

#include "EtwMonitorView.h"

namespace ksword::features::monitor {

HWND createMonitorFeaturePage(HWND parent, const RECT& bounds) {
    return createEtwMonitorPage(parent, bounds);
}

bool requestMonitorFeatureProcess(HWND page, const DWORD processId) {
    return requestEtwMonitorProcessFilter(page, processId);
}

} // namespace Ksword::Features::Monitor

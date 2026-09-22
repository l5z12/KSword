#include "StartupDock.Internal.h"

using namespace startup_dock_detail;

void StartupDock::appendHiddenEntries(std::vector<StartupEntry>* entryListOut)
{
    // Hidden item detection is performed entirely within the ks::startup backend:
    // - The backend obtains two system views for the same object (kernel vs. Win32, registry vs. SCM,
    //   TaskCache vs. Task Scheduler API, etc.) and compiles mismatches into a std::vector<StartupEntry>.
    // - The UI layer is responsible only for display, filtering, and the right-click menu; it does not participate in judgment.
    // - Return value: none; results are appended directly.
    appendBackendStartupEntries(
        entryListOut,
        ks::startup::enumerateHiddenEntries());
}

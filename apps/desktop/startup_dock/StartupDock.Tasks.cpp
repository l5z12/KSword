#include "StartupDock.Internal.h"

using namespace startup_dock_detail;

void StartupDock::appendTaskEntries(std::vector<StartupEntry>* entryListOut)
{
    // Task enumeration backend has been migrated to ks::startup:
    // The backend internally handles PowerShell calls and JSON parsing.
    // - The UI layer only receives std::string records and converts them to QString;
    // - Return value: none; results are appended directly.
    appendBackendStartupEntries(
        entryListOut,
        ks::startup::enumerateTaskEntries());
}

#include "StartupDock.Internal.h"

using namespace startup_dock_detail;

void StartupDock::appendWmiEntries(std::vector<StartupEntry>* entryListOut)
{
    // WMI persistence queries and JSON parsing have been migrated to ks::startup:
    // - The backend internally encapsulates PowerShell/WMI output into std::vector<StartupEntry>.
    // - The UI layer is responsible only for display, filtering, and the right-click menu;
    // - Return value: none; results are appended directly.
    appendBackendStartupEntries(
        entryListOut,
        ks::startup::enumerateWmiEntries());
}

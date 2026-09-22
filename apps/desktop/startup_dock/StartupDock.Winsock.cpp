#include "StartupDock.Internal.h"

using namespace startup_dock_detail;

void StartupDock::appendWinsockEntries(std::vector<StartupEntry>* entryListOut)
{
    // Winsock Provider/Catalog registry enumeration has been moved to ks::startup.
    // - The backend returns unified records for Catalog_Entries/Catalog_Entries64.
    // - The UI layer continues to write records into the advanced registry tree;
    // - Return value: none; results are appended directly.
    appendBackendStartupEntries(
        entryListOut,
        ks::startup::enumerateWinsockEntries());
}

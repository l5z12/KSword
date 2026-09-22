#include "StartupDock.Internal.h"

using namespace startup_dock_detail;

void StartupDock::appendLogonEntries(std::vector<StartupEntry>* entryListOut)
{
    // StartupDock is only responsible for adapting non-UI backend records into a Qt table model:
    // - Input entryListOut: Target for appending UI cache entries;
    // - Processing logic: call ks::startup for logon entries enumeration, then uniformly convert fields.
    // - Return value: None; conversion results are appended directly to entryListOut.
    appendBackendStartupEntries(
        entryListOut,
        ks::startup::enumerateLogonEntries());
}

void StartupDock::appendAdvancedRegistryEntries(std::vector<StartupEntry>* entryListOut)
{
    // The actual enumeration of advanced registry startup entries has been moved to ksword/startup:
    // - The UI layer no longer directly iterates over registry locations such as Run, Explorer, Winlogon, LSA, or COM.
    // - Here, only the adaptation boundary before Qt string/icon rendering is retained;
    // - Return value: None. Results are appended to entryListOut.
    appendBackendStartupEntries(
        entryListOut,
        ks::startup::enumerateAdvancedRegistryEntries());
}

#include "StartupDock.Internal.h"

using namespace startup_dock_detail;

void StartupDock::appendServiceEntries(std::vector<StartupEntry>* entryListOut)
{
    // Service enumeration backend has been migrated to ks::startup:
    // - Input entryListOut: Full cache of StartupDock.
    // - Handling logic: enumerate auto-start Win32 services and convert them to UI records.
    // - Return value: none; results are appended directly.
    appendBackendStartupEntries(
        entryListOut,
        ks::startup::enumerateServiceEntries());
}

void StartupDock::appendDriverEntries(std::vector<StartupEntry>* entryListOut)
{
    // Driver service enumeration backend has been migrated to ks::startup:
    // - Input entryListOut: Full cache of StartupDock.
    // - Logic: enumerate boot/system/auto driver entries and convert to UI records;
    // - Return value: none; results are appended directly.
    appendBackendStartupEntries(
        entryListOut,
        ks::startup::enumerateDriverEntries());
}

#pragma once

// ============================================================
// MonitorAgent.h
// Purpose:
// 1) Expose initialization and stop interfaces for the DLL entry point;
// 2) Give the Hook layer access to the current monitoring configuration and stop state;
// 3) Centralize APIMonitor_x64 global runtime state behind a small set of functions.
// ============================================================

#include "pch.h"
#include "core/MonitorConfig.h"

namespace apimon
{
    // onProcessAttach：
    // - Purpose: Start the background worker thread during DLL_PROCESS_ATTACH;
    // - Call: Only allowed to be called by dllmain.cpp.
    void onProcessAttach(HMODULE moduleHandle);

    // onProcessDetach：
    // - Purpose: Send stop signal when DLL_PROCESS_DETACH occurs;
    // - Call: Only allowed to be called by dllmain.cpp.
    void onProcessDetach();

    // activeConfig：
    // - Purpose: Returns the currently loaded monitoring configuration.
    // - Note: The Hook layer uses this config to determine which categories are enabled.
    const MonitorConfig& activeConfig();

    // replaceActiveConfig：
    // - Purpose: Replace the current runtime configuration with a new one.
    // - Call: Called once by the background worker thread after reading the INI file.
    void replaceActiveConfig(const MonitorConfig& configValue);

    // stopRequested：
    // - Purpose: Check if a stop request has been received for the current monitoring.
    // - Call: Allows background threads and the Hook layer to reduce additional processing.
    bool stopRequested();

    // requestStop：
    // - Purpose: Set the global stop flag;
    // - Call: Can be invoked from background threads or the DllMain Detach path.
    void requestStop();
}

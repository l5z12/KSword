#pragma once

#include "CePluginSdk.h"

#include <Windows.h>

namespace ksword::ce
{
    // initializeBridge：
    // - Input: CE exported function table and this plugin's ID.
    // - Processing: Verify the driver, save original functions, and install four R0 bridge hooks.
    // - Returns: TRUE on success; leaves no partial function table on failure.
    BOOL initializeBridge(ExportedFunctions* exportedFunctions, int pluginId);

    // disableBridge：
    // - Inputs: None.
    // - Processing: Restore the original function and unregister notifications only if the function slot still points to this plugin.
    // - Returns: TRUE when cleanup is complete.
    BOOL disableBridge();

    // notifyFunctionPointersChanged：
    // - Input: CE reserved parameter.
    // - Processing: Reinstall KSword hooks after CE rebuilds the access function table.
    // - Returns: Nothing.
    void __stdcall notifyFunctionPointersChanged(int reserved);
}

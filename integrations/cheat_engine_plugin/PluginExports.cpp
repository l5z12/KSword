#include "KswordCeBridge.h"

#include <Windows.h>

namespace
{
    char gPluginName[] = "KSword Driver Bridge 1.0";
}

// CEPlugin_GetVersion：
// - Input: version structure and size allocated by CE.
// - Processing: Declare SDK v6 compatibility and stable plugin name.
// - Returns: TRUE when the structure is writable.
extern "C" BOOL __stdcall CEPlugin_GetVersion(
    ksword::ce::PluginVersion* const pluginVersion,
    const int pluginVersionSize)
{
    try
    {
        if (pluginVersion == nullptr ||
            pluginVersionSize < static_cast<int>(
                sizeof(ksword::ce::PluginVersion)))
        {
            return FALSE;
        }

        pluginVersion->version = ksword::ce::kCeSdkVersion;
        pluginVersion->pluginName = gPluginName;
        return TRUE;
    }
    catch (...)
    {
        return FALSE;
    }
}

// CEPlugin_InitializePlugin：
// - Input: CE function table and plugin ID allocated by CE.
// - Processing: Delegate to the bridge layer to verify the driver and install access functions.
// - Returns: TRUE if the plugin is available.
extern "C" BOOL __stdcall CEPlugin_InitializePlugin(
    ksword::ce::ExportedFunctions* const exportedFunctions,
    const int pluginId)
{
    try
    {
        return ksword::ce::initializeBridge(exportedFunctions, pluginId);
    }
    catch (...)
    {
        ::SetLastError(ERROR_GEN_FAILURE);
        return FALSE;
    }
}

// CEPlugin_DisablePlugin：
// - Inputs: None.
// - Processing: Restore the original CE function and unregister the callback.
// - Returns: TRUE when cleanup is complete.
extern "C" BOOL __stdcall CEPlugin_DisablePlugin()
{
    try
    {
        return ksword::ce::disableBridge();
    }
    catch (...)
    {
        ::SetLastError(ERROR_GEN_FAILURE);
        return FALSE;
    }
}

// DllMain：
// - Input: Windows DLL lifecycle parameters;
// - Processing: Disable unnecessary thread notifications; business initialization is permitted only via explicit CE invocation.
// - Returns: Always allows DLL loading.
BOOL APIENTRY DllMain(
    const HMODULE moduleHandle,
    const DWORD reason,
    LPVOID const reserved)
{
    UNREFERENCED_PARAMETER(reserved);
    if (reason == DLL_PROCESS_ATTACH)
    {
        ::DisableThreadLibraryCalls(moduleHandle);
    }
    return TRUE;
}

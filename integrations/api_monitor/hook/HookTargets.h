#pragma once

// ============================================================
// hook/HookTargets.h
// Purpose:
// 1) Implement specific WinAPI Detour functions.
// 2) Install/uninstall hooks for each category according to the current configuration.
// 3) Install hooks for newly loaded modules that failed to hook during DLL runtime.
// ============================================================

#include "pch.h"

namespace apimon
{
    bool installConfiguredHooks(std::wstring* errorTextOut);
    void uninstallConfiguredHooks();
    void retryPendingHooks();
}

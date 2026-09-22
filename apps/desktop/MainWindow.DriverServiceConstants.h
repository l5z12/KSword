#pragma once

// Implementation details shared by mainWindow's responsibility-specific units.
// Public window API remains in mainWindow.h.
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

namespace ksword::ui::main_window
{
    inline constexpr wchar_t kR0DriverServiceName[] = L"KswordARK";

    inline constexpr wchar_t kR0DriverDisplayName[] = L"KswordARK Driver Service";

    inline constexpr DWORD kR0ServiceStartWaitTimeoutMs = 9000;

    inline constexpr DWORD kR0ServiceStopWaitTimeoutMs = 30000;

    inline constexpr int kR0LogConnectRetrySleepMs = 260;
}

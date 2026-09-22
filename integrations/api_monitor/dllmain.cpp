#include "pch.h"
#include "MonitorAgent.h"

// ============================================================
// dllmain.cpp
// Purpose:
// 1) Serve as the DLL entry point for APIMonitor_x64;
// 2) Responsible only for minimal forwarding to MonitorAgent, avoiding accumulation of business logic within DllMain;
// 3) Keep DllMain short to reduce Loader Lock risks.
// ============================================================

BOOL APIENTRY DllMain(HMODULE moduleHandle, DWORD reasonCode, LPVOID reservedPointer)
{
    (void)reservedPointer;

    switch (reasonCode)
    {
    case DLL_PROCESS_ATTACH:
        apimon::onProcessAttach(moduleHandle);
        break;
    case DLL_PROCESS_DETACH:
        apimon::onProcessDetach();
        break;
    default:
        break;
    }
    return TRUE;
}

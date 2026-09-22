#pragma once

// ============================================================
// core/MonitorPipe.h
// Purpose:
// 1) Responsible for creating and closing the named pipe server on the Agent side;
// 2) Assemble Hook events into fixed-length event packets and send them to the UI.
// 3) Provide a check to determine if the current handle is a monitoring pipe, preventing WriteFile Hook self-recursion.
// ============================================================

#include "pch.h"
#include "MonitorConfig.h"

namespace apimon
{
    bool startMonitorPipeServer(const MonitorConfig& configValue, std::wstring* errorTextOut);
    void stopMonitorPipeServer();
    bool sendMonitorEvent(
        ks::winapi_monitor::EventCategory categoryValue,
        const wchar_t* moduleName,
        const wchar_t* apiName,
        std::int32_t resultCode,
        const std::wstring& detailText);
    bool sendMonitorEventRaw(
        ks::winapi_monitor::EventCategory categoryValue,
        const wchar_t* moduleName,
        const wchar_t* apiName,
        std::int32_t resultCode,
        const wchar_t* detailText);
    std::uint32_t flushPendingMonitorEvents(std::uint32_t maxPacketsToFlush);
    bool isMonitorPipeHandle(HANDLE handleValue);
}

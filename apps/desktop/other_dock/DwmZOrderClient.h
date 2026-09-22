#pragma once

#include "../../../shared/window/DwmZOrderProtocol.h"
#include <string>
#include <mutex>

namespace ks::dwm_order
{
    enum class Stage { kWindow, kAgentFile, kDwmProcess, kPrepareAgent, kLoadAgent, kRequest, kReceipt };
    struct Reply
    {
        Response response;
        Stage stage = Stage::kWindow;
        std::uint32_t error = 0;
        std::uint32_t loaderThreadExitCode = 0;
        std::uint32_t requestThreadExitCode = 0;
        bool loaderCompleted = false;
    };

    bool captureWindow(std::uint64_t hwnd, WindowIdentity& identity, std::uint32_t& error);
    // All window-order transactions share this lock, including input-mode rollback.
    std::recursive_mutex& operationMutex();
    Reply executeRequest(const Request& request, const std::wstring& agentPath, bool allowLoad = false);
}

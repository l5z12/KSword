#include "ArkDriverClient.h"
#include "ArkDriverResponseSupport.h"

#include <sstream>

namespace ksword::ark
{
// querySystemTime：
    // - Call: Invoked upon page entry, periodic refresh, or before control.
    // - Input: no business parameters, only sends a versioned query packet;
    // - Returns: Complete system variable-speed status and protocol diagnostics.
    SystemTimeQueryResult DriverClient::querySystemTime() const
    {
        SystemTimeQueryResult result{};
        KSWORD_ARK_QUERY_SYSTEM_TIME_REQUEST request{};

        request.version =
            KSWORD_ARK_SYSTEM_TIME_PROTOCOL_VERSION;
        request.size = sizeof(request);
        result.io = deviceIoControl(
            IOCTL_KSWORD_ARK_QUERY_SYSTEM_TIME,
            &request,
            static_cast<unsigned long>(sizeof(request)),
            &result.response,
            static_cast<unsigned long>(sizeof(result.response)));
        result.unsupported = !result.io.ok &&
            detail::isUnsupportedProtocolError(result.io.win32Error);

        if (result.io.ok &&
            (result.io.bytesReturned < sizeof(result.response) ||
             result.response.version !=
                KSWORD_ARK_SYSTEM_TIME_PROTOCOL_VERSION ||
             result.response.size != sizeof(result.response)))
        {
            result.io.ok = false;
            result.io.win32Error = ERROR_INVALID_DATA;
        }
        result.io.ntStatus = result.response.lastStatus;

        std::ostringstream stream;
        stream
            << "system-time query status="
            << result.response.status
            << ", flags=0x" << std::hex
            << result.response.stateFlags
            << ", generation=" << std::dec
            << result.response.generation
            << ", command=" << result.response.command
            << ", factor=" << result.response.factor
            << ", backend=" << result.response.backend
            << ", resolutionMode="
            << result.response.resolutionMode
            << ", build=" << result.response.osBuildNumber;
        if (result.unsupported)
        {
            stream << ", unsupported=true";
        }
        result.io.message = stream.str();
        return result;
    }

    // controlSystemTime：
    // - Call: Set acceleration/deceleration after user confirmation, or unconditionally restore 1x.
    // - Input: command, multiplier, timing backend, parsing mode, expected generation, and UI confirmation status;
    // - Return: State before and after the action; all device access remains encapsulated within ArkDriverClient.
    SystemTimeControlResult DriverClient::controlSystemTime(
        const unsigned long command,
        const unsigned long factor,
        const unsigned long backend,
        const unsigned long resolutionMode,
        const unsigned long expectedGeneration,
        const bool uiConfirmed) const
    {
        SystemTimeControlResult result{};
        KSWORD_ARK_CONTROL_SYSTEM_TIME_REQUEST request{};

        request.version =
            KSWORD_ARK_SYSTEM_TIME_PROTOCOL_VERSION;
        request.size = sizeof(request);
        request.command = command;
        request.factor = factor;
        request.backend = backend;
        request.resolutionMode = resolutionMode;
        request.expectedGeneration = expectedGeneration;
        if (uiConfirmed)
        {
            request.flags |=
                KSWORD_ARK_SYSTEM_TIME_CONTROL_FLAG_UI_CONFIRMED;
            request.confirmationToken =
                KSWORD_ARK_SYSTEM_TIME_CONFIRMATION_TOKEN;
        }

        result.io = deviceIoControl(
            IOCTL_KSWORD_ARK_CONTROL_SYSTEM_TIME,
            &request,
            static_cast<unsigned long>(sizeof(request)),
            &result.response,
            static_cast<unsigned long>(sizeof(result.response)));
        result.unsupported = !result.io.ok &&
            detail::isUnsupportedProtocolError(result.io.win32Error);

        if (result.io.ok &&
            (result.io.bytesReturned < sizeof(result.response) ||
             result.response.version !=
                KSWORD_ARK_SYSTEM_TIME_PROTOCOL_VERSION ||
             result.response.size != sizeof(result.response)))
        {
            result.io.ok = false;
            result.io.win32Error = ERROR_INVALID_DATA;
        }
        result.io.ntStatus = result.response.lastStatus;

        std::ostringstream stream;
        stream
            << "system-time control command="
            << command
            << ", requestedFactor=" << factor
            << ", backend=" << backend
            << ", resolutionMode=" << resolutionMode
            << ", status=" << result.response.status
            << ", oldFlags=0x" << std::hex
            << result.response.oldStateFlags
            << ", newFlags=0x"
            << result.response.newStateFlags
            << ", generation=" << std::dec
            << result.response.oldGeneration
            << "->" << result.response.newGeneration;
        if (result.unsupported)
        {
            stream << ", unsupported=true";
        }
        result.io.message = stream.str();
        return result;
    }
}

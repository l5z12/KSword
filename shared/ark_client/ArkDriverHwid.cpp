#include "ArkDriverClient.h"
#include "ArkDriverResponseSupport.h"

#include <sstream>

namespace ksword::ark
{
    namespace
    {

        // formatHwidIoMessage：
        // - Input: Operation name, IO result, and optional response;
        // - Processing: Unified concatenation of log/status bar text.
        // - Return: short message for UI.
        std::string formatHwidIoMessage(
            const char* operationName,
            const IoResult& io,
            const KSWORD_ARK_HWID_DISPATCH_RESPONSE& response)
        {
            std::ostringstream stream;
            stream << operationName
                << ", ioctl=" << (io.ok ? "ok" : "fail")
                << ", win32=" << io.win32Error
                << ", bytes=" << io.bytesReturned
                << ", status=" << response.overallStatus
                << ", active=0x" << std::hex << response.activeTargetFlags
                << ", failed=0x" << response.failedTargetFlags;
            return stream.str();
        }
    }

    HwidDispatchResult DriverClient::queryHwidDispatchState() const
    {
        // response usage: Receive the R0 fixed status packet.
        HwidDispatchResult result{};

        result.io = deviceIoControl(
            IOCTL_KSWORD_ARK_HWID_DISPATCH_QUERY,
            nullptr,
            0UL,
            &result.response,
            static_cast<unsigned long>(sizeof(result.response)));
        result.unsupported = !result.io.ok && detail::isUnsupportedIoctlError(result.io.win32Error);
        if (result.io.bytesReturned >= sizeof(result.response))
        {
            result.io.ntStatus = result.response.lastStatus;
        }
        result.io.message = result.unsupported
            ? "IOCTL_KSWORD_ARK_HWID_DISPATCH_QUERY unsupported by current driver"
            : formatHwidIoMessage("IOCTL_KSWORD_ARK_HWID_DISPATCH_QUERY", result.io, result.response);
        return result;
    }

    HwidDispatchResult DriverClient::controlHwidDispatch(
        const KSWORD_ARK_HWID_DISPATCH_CONTROL_REQUEST& request) const
    {
        // mutableRequest: Required by DeviceIoControl as a non-const input pointer; protocol content is not modified in R3.
        KSWORD_ARK_HWID_DISPATCH_CONTROL_REQUEST mutableRequest = request;
        HwidDispatchResult result{};

        result.io = deviceIoControl(
            IOCTL_KSWORD_ARK_HWID_DISPATCH_CONTROL,
            &mutableRequest,
            static_cast<unsigned long>(sizeof(mutableRequest)),
            &result.response,
            static_cast<unsigned long>(sizeof(result.response)));
        result.unsupported = !result.io.ok && detail::isUnsupportedIoctlError(result.io.win32Error);
        if (result.io.bytesReturned >= sizeof(result.response))
        {
            result.io.ntStatus = result.response.lastStatus;
        }
        result.io.message = result.unsupported
            ? "IOCTL_KSWORD_ARK_HWID_DISPATCH_CONTROL unsupported by current driver"
            : formatHwidIoMessage("IOCTL_KSWORD_ARK_HWID_DISPATCH_CONTROL", result.io, result.response);
        return result;
    }
}

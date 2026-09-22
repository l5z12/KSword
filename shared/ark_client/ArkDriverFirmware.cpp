#include "ArkDriverClient.h"
#include "ArkDriverResponseSupport.h"

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <sstream>
#include <utility>
#include <vector>

namespace ksword::ark
{
    using detail::isUnsupportedIoctlError;
    IoResult DriverClient::experimentalReturnToFirmware() const
    {
        KSWORD_ARK_EXPERIMENTAL_RETURN_TO_FIRMWARE_REQUEST request{};
        request.action = KSWORD_ARK_FIRMWARE_RETURN_ACTION_HAL_REBOOT_ROUTINE;
        request.flags = KSWORD_ARK_FIRMWARE_RETURN_FLAG_UI_CONFIRMED;
        request.confirmationToken = KSWORD_ARK_FIRMWARE_RETURN_CONFIRMATION_TOKEN;
        IoResult result = deviceIoControl(
            IOCTL_KSWORD_ARK_EXPERIMENTAL_RETURN_TO_FIRMWARE,
            &request,
            static_cast<unsigned long>(sizeof(request)),
            nullptr,
            0);

        std::ostringstream stream;
        stream << "rawApi=HalReturnToFirmware(HalRebootRoutine)"
            << ", scope=machine"
            << ", bytesReturned=" << result.bytesReturned;
        if (result.ok)
        {
            stream << ", ioctl=returned-success";
        }
        else
        {
            stream << ", ioctl=fail-or-returned, error=" << result.win32Error;
        }
        result.message = stream.str();
        return result;
    }
}

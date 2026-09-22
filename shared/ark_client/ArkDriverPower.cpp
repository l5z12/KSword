#include "ArkDriverClient.h"
#include "ArkDriverResponseSupport.h"

#include <sstream>

static_assert(sizeof(KSWORD_ARK_CPU_POWER_CONTROL_REQUEST) == 144U);
static_assert(sizeof(KSWORD_ARK_CPU_POWER_RESPONSE) == 352U);

namespace ksword::ark
{
    namespace
    {

        // formatCpuPowerIoMessage: Generates stable diagnostic text containing capabilities, flags, and semantic status.
        std::string formatCpuPowerIoMessage(
            const char* operationName,
            const IoResult& io,
            const KSWORD_ARK_CPU_POWER_RESPONSE& response)
        {
            std::ostringstream stream;
            stream << operationName
                << ", ioctl=" << (io.ok ? "ok" : "fail")
                << ", win32=" << io.win32Error
                << ", bytes=" << io.bytesReturned
                << ", status=0x" << std::hex
                << static_cast<unsigned long>(response.lastStatus)
                << ", fields=0x" << response.fieldFlags
                << ", response=0x" << response.responseFlags
                << ", capability=0x" << response.capabilityFlags
                << std::dec
                << ", reason=" << response.failureReason
                << ", requestedMultiplier=" << response.requestedMultiplier
                << ", currentMultiplier=" << response.currentMultiplier
                << ", updated=" << response.updatedProcessorCount
                << ", failed=" << response.failedProcessorCount;
            return stream.str();
        }
    }

    CpuPowerResult DriverClient::queryCpuPowerState() const
    {
        // result.response is used directly as a fixed output buffer.
        CpuPowerResult result{};
        result.io = deviceIoControl(
            IOCTL_KSWORD_ARK_QUERY_CPU_POWER,
            nullptr,
            0UL,
            &result.response,
            static_cast<unsigned long>(sizeof(result.response)));
        // Old driver compatibility status is strictly separated from AMD/locked business status.
        result.unsupported = !result.io.ok &&
            detail::isMissingIoctlError(result.io.win32Error);
        if (result.io.bytesReturned >= sizeof(result.response))
        {
            result.io.ntStatus = result.response.lastStatus;
        }
        result.io.message = result.unsupported
            ? "IOCTL_KSWORD_ARK_QUERY_CPU_POWER unsupported by current driver"
            : formatCpuPowerIoMessage(
                "IOCTL_KSWORD_ARK_QUERY_CPU_POWER",
                result.io,
                result.response);
        return result;
    }

    CpuPowerResult DriverClient::controlCpuPower(
        const KSWORD_ARK_CPU_POWER_CONTROL_REQUEST& request) const
    {
        // DeviceIoControl requires a non-const input pointer; mutableRequest does not modify the caller's object.
        KSWORD_ARK_CPU_POWER_CONTROL_REQUEST mutableRequest = request;
        CpuPowerResult result{};
        result.io = deviceIoControl(
            IOCTL_KSWORD_ARK_CONTROL_CPU_POWER,
            &mutableRequest,
            static_cast<unsigned long>(sizeof(mutableRequest)),
            &result.response,
            static_cast<unsigned long>(sizeof(result.response)));
        // Parameter/Lock/Security policy failure must not be falsely reported as 'old driver'.
        result.unsupported = !result.io.ok &&
            detail::isMissingIoctlError(result.io.win32Error);
        if (result.io.bytesReturned >= sizeof(result.response))
        {
            result.io.ntStatus = result.response.lastStatus;
        }
        result.io.message = result.unsupported
            ? "IOCTL_KSWORD_ARK_CONTROL_CPU_POWER unsupported by current driver"
            : formatCpuPowerIoMessage(
                "IOCTL_KSWORD_ARK_CONTROL_CPU_POWER",
                result.io,
                result.response);
        return result;
    }
}

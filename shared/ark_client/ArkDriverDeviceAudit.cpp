#include "ArkDriverClient.h"
#include "ArkDriverAuditSupport.h"

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <iterator>
#include <limits>
#include <sstream>
#include <string>
#include <type_traits>
#include <vector>

namespace ksword::ark
{
    using namespace detail::audit;
    namespace
    {
    // queryDeviceAuditRows: Encapsulates unified device audit IOCTLs for Device, Input, USB, and GPU categories.
    DeviceAuditResult queryDeviceAuditRows(
        const DriverClient& client,
        const unsigned long ioctlCode,
        const unsigned long profileFlags,
        const std::wstring& targetName,
        const unsigned long maxRows,
        const unsigned long maxAttachedDepth,
        const char* const operationName)
    {
        DeviceAuditResult result{};
        KSWORD_ARK_QUERY_DEVICE_AUDIT_REQUEST request{};
        request.size = sizeof(request);
        request.version = KSWORD_ARK_DEVICE_AUDIT_PROTOCOL_VERSION;
        request.profileFlags = profileFlags;
        request.maxRows = maxRows;
        request.maxAttachedDepth = maxAttachedDepth;
        copyAuditWideToFixed(request.targetName, KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS, targetName);
        std::vector<std::uint8_t> responseBuffer(kDefaultAuditBufferBytes, 0U);
        result.io = client.deviceIoControl(ioctlCode, &request, sizeof(request), responseBuffer.data(), static_cast<unsigned long>(responseBuffer.size()));
        if (!result.io.ok)
        {
            markUnsupportedIfNeeded(result, operationName);
            return result;
        }

        constexpr std::size_t kHeaderSize = sizeof(KSWORD_ARK_QUERY_DEVICE_AUDIT_RESPONSE) - sizeof(KSWORD_ARK_DEVICE_AUDIT_ENTRY);
        const auto* response = reinterpret_cast<const KSWORD_ARK_QUERY_DEVICE_AUDIT_RESPONSE*>(responseBuffer.data());
        const std::size_t kParsedCount = validateAuditRows(result.io, kHeaderSize, response->entrySize, sizeof(KSWORD_ARK_DEVICE_AUDIT_ENTRY), response->returnedCount, operationName);
        if (!result.io.ok)
        {
            return result;
        }

        result.version = response->version;
        result.status = response->queryStatus;
        result.profileFlags = response->profileFlags;
        result.responseFlags = response->responseFlags;
        result.totalCount = response->totalCount;
        result.returnedCount = response->returnedCount;
        result.entrySize = response->entrySize;
        result.targetCount = response->targetCount;
        result.driverCount = response->driverCount;
        result.deviceCount = response->deviceCount;
        result.lastStatus = response->lastStatus;
        result.io.ntStatus = response->lastStatus;
        result.entries = parseVariableRows<KSWORD_ARK_DEVICE_AUDIT_ENTRY>(responseBuffer, kHeaderSize, response->entrySize, kParsedCount);
        result.io.message = appendAuditSummary(operationName, result.totalCount, result.returnedCount, result.entries.size(), result.io.bytesReturned);
        return result;
    }
    }

    DeviceAuditResult DriverClient::queryDeviceStackAudit(const std::wstring& targetName, const unsigned long maxRows, const unsigned long maxAttachedDepth) const
    {
        return queryDeviceAuditRows(*this, IOCTL_KSWORD_ARK_QUERY_DEVICE_STACK_AUDIT, KSWORD_ARK_DEVICE_AUDIT_PROFILE_DEVICE_STACK, targetName, maxRows, maxAttachedDepth, "IOCTL_KSWORD_ARK_QUERY_DEVICE_STACK_AUDIT");
    }

    DeviceAuditResult DriverClient::queryInputStackAudit(const std::wstring& targetName, const unsigned long maxRows, const unsigned long maxAttachedDepth) const
    {
        return queryDeviceAuditRows(*this, IOCTL_KSWORD_ARK_QUERY_INPUT_STACK_AUDIT, KSWORD_ARK_DEVICE_AUDIT_PROFILE_INPUT_STACK, targetName, maxRows, maxAttachedDepth, "IOCTL_KSWORD_ARK_QUERY_INPUT_STACK_AUDIT");
    }

    DeviceAuditResult DriverClient::queryUsbTopologyAudit(const std::wstring& targetName, const unsigned long maxRows, const unsigned long maxAttachedDepth) const
    {
        return queryDeviceAuditRows(*this, IOCTL_KSWORD_ARK_QUERY_USB_TOPOLOGY_AUDIT, KSWORD_ARK_DEVICE_AUDIT_PROFILE_USB_TOPOLOGY, targetName, maxRows, maxAttachedDepth, "IOCTL_KSWORD_ARK_QUERY_USB_TOPOLOGY_AUDIT");
    }

    DeviceAuditResult DriverClient::queryGpuDisplayWatchdogAudit(const std::wstring& targetName, const unsigned long maxRows, const unsigned long maxAttachedDepth) const
    {
        return queryDeviceAuditRows(*this, IOCTL_KSWORD_ARK_QUERY_GPU_DISPLAY_WATCHDOG_AUDIT, KSWORD_ARK_DEVICE_AUDIT_PROFILE_GPU_DISPLAY_WATCHDOG, targetName, maxRows, maxAttachedDepth, "IOCTL_KSWORD_ARK_QUERY_GPU_DISPLAY_WATCHDOG_AUDIT");
    }
}

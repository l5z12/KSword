#include "ArkDriverClient.h"
#include "ArkDriverResponseSupport.h"

#include <algorithm>
#include <cstddef>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace ksword::ark
{
// Note: Query the KswordARK dispatch registry via ArkDriverClient.
    IoctlRegistryQueryResult DriverClient::queryIoctlRegistry(
        const unsigned long flags,
        const unsigned long maxEntries) const
    {
        IoctlRegistryQueryResult queryResult{};
        KSWORD_ARK_QUERY_IOCTL_REGISTRY_REQUEST request{};
        request.version = KSWORD_ARK_IOCTL_REGISTRY_PROTOCOL_VERSION;
        request.flags = flags;
        request.maxEntries = maxEntries;

        constexpr std::size_t kHeaderSize = KSWORD_ARK_IOCTL_REGISTRY_RESPONSE_HEADER_SIZE;
        const std::size_t kOutputSize = kHeaderSize +
            (static_cast<std::size_t>(std::min<unsigned long>(
                maxEntries == 0UL ? KSWORD_ARK_IOCTL_REGISTRY_MAX_ENTRIES : maxEntries,
                KSWORD_ARK_IOCTL_REGISTRY_MAX_ENTRIES)) * sizeof(KSWORD_ARK_IOCTL_REGISTRY_ENTRY));
        std::vector<std::uint8_t> responseBuffer(kOutputSize, 0U);
        queryResult.io = deviceIoControl(
            IOCTL_KSWORD_ARK_QUERY_IOCTL_REGISTRY,
            &request,
            static_cast<unsigned long>(sizeof(request)),
            responseBuffer.data(),
            static_cast<unsigned long>(responseBuffer.size()));
        if (!queryResult.io.ok)
        {
            queryResult.unsupported = detail::isUnsupportedIoctlError(queryResult.io.win32Error);
            queryResult.io.message = queryResult.unsupported
                ? "IOCTL_KSWORD_ARK_QUERY_IOCTL_REGISTRY unsupported or driver version is too old"
                : "DeviceIoControl(IOCTL_KSWORD_ARK_QUERY_IOCTL_REGISTRY) failed, error=" +
                    std::to_string(queryResult.io.win32Error);
            return queryResult;
        }

        if (queryResult.io.bytesReturned < kHeaderSize)
        {
            queryResult.io.ok = false;
            queryResult.io.message = "ioctl-registry response too small, bytesReturned=" +
                std::to_string(queryResult.io.bytesReturned);
            return queryResult;
        }

        const auto* response = reinterpret_cast<const KSWORD_ARK_QUERY_IOCTL_REGISTRY_RESPONSE*>(responseBuffer.data());
        if (response->version != KSWORD_ARK_IOCTL_REGISTRY_PROTOCOL_VERSION ||
            response->entrySize < sizeof(KSWORD_ARK_IOCTL_REGISTRY_ENTRY))
        {
            queryResult.io.ok = false;
            queryResult.io.message = "ioctl-registry response header invalid";
            return queryResult;
        }

        queryResult.version = response->version;
        queryResult.status = response->status;
        queryResult.totalCount = response->totalCount;
        queryResult.returnedCount = response->returnedCount;
        queryResult.duplicateCount = response->duplicateCount;
        queryResult.lastStatus = response->lastStatus;
        const std::size_t kAvailableCount =
            (queryResult.io.bytesReturned - kHeaderSize) / response->entrySize;
        const std::size_t kParsedCount = std::min<std::size_t>(
            static_cast<std::size_t>(response->returnedCount), kAvailableCount);
        queryResult.entries.reserve(kParsedCount);
        for (std::size_t index = 0U; index < kParsedCount; ++index)
        {
            const std::size_t kOffset = kHeaderSize + (index * response->entrySize);
            const auto* source = reinterpret_cast<const KSWORD_ARK_IOCTL_REGISTRY_ENTRY*>(responseBuffer.data() + kOffset);
            IoctlRegistryEntry entry{};
            entry.ioControlCode = source->ioControlCode;
            entry.functionNumber = source->functionNumber;
            entry.method = source->method;
            entry.access = source->access;
            entry.flags = source->flags;
            entry.requiredCapability = source->requiredCapability;
            entry.handlerAddress = source->handlerAddress;
            entry.name = detail::readFixedString(source->name, KSWORD_ARK_IOCTL_REGISTRY_NAME_CHARS);
            queryResult.entries.push_back(std::move(entry));
        }

        std::ostringstream message;
        message << "version=" << queryResult.version
            << ", status=" << queryResult.status
            << ", entries=" << queryResult.entries.size() << "/" << queryResult.totalCount
            << ", duplicates=" << queryResult.duplicateCount;
        queryResult.io.message = message.str();
        return queryResult;
    }
}

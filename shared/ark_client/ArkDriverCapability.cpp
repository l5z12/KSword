#include "ArkDriverClient.h"
#include "ArkDriverResponseSupport.h"

#include <algorithm>
#include <string>
#include <utility>
#include <vector>

namespace ksword::ark
{
// queryDriverCapabilities:
    // - Request R0 Phase 1 for unified capabilities, protocols, security policies, and error summaries;
    // - No input parameters;
    // - Returns: Parsed status field and capability matrix.
    DriverCapabilitiesQueryResult DriverClient::queryDriverCapabilities() const
    {
        DriverCapabilitiesQueryResult result{};
        std::vector<std::uint8_t> responseBuffer(64U * 1024U, 0U);

        result.io = deviceIoControl(
            IOCTL_KSWORD_ARK_QUERY_DRIVER_CAPABILITIES,
            nullptr,
            0UL,
            responseBuffer.data(),
            static_cast<unsigned long>(responseBuffer.size()));
        if (!result.io.ok)
        {
            result.io.message = "DeviceIoControl(IOCTL_KSWORD_ARK_QUERY_DRIVER_CAPABILITIES) failed, error=" + std::to_string(result.io.win32Error);
            return result;
        }

        constexpr std::size_t kHeaderSize =
            sizeof(KSWORD_ARK_QUERY_DRIVER_CAPABILITIES_RESPONSE) -
            sizeof(KSWORD_ARK_FEATURE_CAPABILITY_ENTRY);
        if (result.io.bytesReturned < kHeaderSize)
        {
            result.io.ok = false;
            result.io.message = "driver capability response too small, bytesReturned=" + std::to_string(result.io.bytesReturned);
            return result;
        }

        const auto* responseHeader = reinterpret_cast<const KSWORD_ARK_QUERY_DRIVER_CAPABILITIES_RESPONSE*>(responseBuffer.data());
        if (responseHeader->version != KSWORD_ARK_DRIVER_CAPABILITY_PROTOCOL_VERSION ||
            responseHeader->entrySize < sizeof(KSWORD_ARK_FEATURE_CAPABILITY_ENTRY))
        {
            result.io.ok = false;
            result.io.message = "driver capability response header invalid.";
            return result;
        }

        result.version = static_cast<std::uint32_t>(responseHeader->version);
        result.driverProtocolVersion = static_cast<std::uint32_t>(responseHeader->driverProtocolVersion);
        result.statusFlags = static_cast<std::uint32_t>(responseHeader->statusFlags);
        result.securityPolicyFlags = static_cast<std::uint32_t>(responseHeader->securityPolicyFlags);
        result.dynDataStatusFlags = static_cast<std::uint32_t>(responseHeader->dynDataStatusFlags);
        result.lastErrorStatus = static_cast<long>(responseHeader->lastErrorStatus);
        result.totalFeatureCount = static_cast<std::uint32_t>(responseHeader->totalFeatureCount);
        result.returnedFeatureCount = static_cast<std::uint32_t>(responseHeader->returnedFeatureCount);
        result.dynDataCapabilityMask = static_cast<std::uint64_t>(responseHeader->dynDataCapabilityMask);
        result.lastErrorSource = detail::readFixedString(responseHeader->lastErrorSource, sizeof(responseHeader->lastErrorSource));
        result.lastErrorSummary = detail::readFixedString(responseHeader->lastErrorSummary, sizeof(responseHeader->lastErrorSummary));

        const std::size_t kAvailableCount =
            (result.io.bytesReturned - kHeaderSize) /
            static_cast<std::size_t>(responseHeader->entrySize);
        const std::size_t kParsedCount = std::min<std::size_t>(
            static_cast<std::size_t>(responseHeader->returnedFeatureCount),
            kAvailableCount);
        result.entries.reserve(kParsedCount);

        for (std::size_t index = 0U; index < kParsedCount; ++index)
        {
            const std::size_t kEntryOffset = kHeaderSize + (index * static_cast<std::size_t>(responseHeader->entrySize));
            if (kEntryOffset + sizeof(KSWORD_ARK_FEATURE_CAPABILITY_ENTRY) > result.io.bytesReturned)
            {
                break;
            }

            const auto* sourceEntry = reinterpret_cast<const KSWORD_ARK_FEATURE_CAPABILITY_ENTRY*>(responseBuffer.data() + kEntryOffset);
            DriverFeatureCapabilityEntry row{};
            row.featureId = static_cast<std::uint32_t>(sourceEntry->featureId);
            row.state = static_cast<std::uint32_t>(sourceEntry->state);
            row.flags = static_cast<std::uint32_t>(sourceEntry->flags);
            row.requiredPolicyFlags = static_cast<std::uint32_t>(sourceEntry->requiredPolicyFlags);
            row.deniedPolicyFlags = static_cast<std::uint32_t>(sourceEntry->deniedPolicyFlags);
            row.requiredDynDataMask = static_cast<std::uint64_t>(sourceEntry->requiredDynDataMask);
            row.presentDynDataMask = static_cast<std::uint64_t>(sourceEntry->presentDynDataMask);
            row.featureName = detail::readFixedString(sourceEntry->featureName, sizeof(sourceEntry->featureName));
            row.stateName = detail::readFixedString(sourceEntry->stateName, sizeof(sourceEntry->stateName));
            row.dependencyText = detail::readFixedString(sourceEntry->dependencyText, sizeof(sourceEntry->dependencyText));
            row.reasonText = detail::readFixedString(sourceEntry->reasonText, sizeof(sourceEntry->reasonText));
            result.entries.push_back(std::move(row));
        }

        result.io.message = "Driver capabilities parsed=" + std::to_string(result.entries.size()) +
            ", total=" + std::to_string(result.totalFeatureCount);
        return result;
    }
}

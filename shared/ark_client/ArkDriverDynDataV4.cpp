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
    template <typename TResult, typename TResponse, typename TEntry>
    TResult queryDynDataV4Rows(const DriverClient& client, const unsigned long ioctlCode, const unsigned long maxRows, const char* const operationName)
    {
        TResult result{};
        std::vector<std::uint8_t> responseBuffer(std::max<std::size_t>(64U * 1024U, sizeof(TResponse) + (static_cast<std::size_t>(maxRows) * sizeof(TEntry))), 0U);
        result.io = client.deviceIoControl(ioctlCode, nullptr, 0UL, responseBuffer.data(), static_cast<unsigned long>(std::min<std::size_t>(responseBuffer.size(), kDefaultAuditBufferBytes)));
        if (!result.io.ok)
        {
            markUnsupportedIfNeeded(result, operationName);
            return result;
        }

        constexpr std::size_t kHeaderSize = sizeof(TResponse) - sizeof(TEntry);
        const auto* response = reinterpret_cast<const TResponse*>(responseBuffer.data());
        const std::size_t kParsedCount = validateAuditRows(result.io, kHeaderSize, response->entrySize, sizeof(TEntry), response->returnedCount, operationName);
        if (!result.io.ok)
        {
            return result;
        }

        result.version = response->version;
        result.totalCount = response->totalCount;
        result.returnedCount = response->returnedCount;
        result.entrySize = response->entrySize;
        result.entries = parseVariableRows<TEntry>(responseBuffer, kHeaderSize, response->entrySize, kParsedCount);
        result.io.message = appendAuditSummary(operationName, result.totalCount, result.returnedCount, result.entries.size(), result.io.bytesReturned);
        return result;
    }
    }

    DynDataV4ApplyResult DriverClient::applyDynDataProfileV4(const DynDataV4ApplyInput& profile) const
    {
        DynDataV4ApplyResult result{};
        if (profile.items.empty() || profile.items.size() > KSW_DYN_V4_MAX_ITEMS_PER_MODULE || profile.capabilityGroups.size() > KSW_DYN_V4_MAX_CAPABILITY_GROUPS_PER_MODULE)
        {
            result.io.ok = false;
            result.io.win32Error = ERROR_INVALID_PARAMETER;
            result.io.message = "DynData v4 profile item/group count invalid.";
            return result;
        }

        const std::size_t kRequestBytes = KSW_APPLY_DYN_PROFILE_V4_REQUEST_HEADER_SIZE + (profile.items.size() * sizeof(KSW_DYN_V4_ITEM_PACKET));
        if (kRequestBytes > static_cast<std::size_t>(std::numeric_limits<unsigned long>::max()))
        {
            result.io.ok = false;
            result.io.win32Error = ERROR_INVALID_PARAMETER;
            result.io.message = "DynData v4 profile request too large.";
            return result;
        }

        std::vector<std::uint8_t> requestBuffer(kRequestBytes, 0U);
        auto* request = reinterpret_cast<KSW_APPLY_DYN_PROFILE_V4_REQUEST*>(requestBuffer.data());
        request->size = static_cast<unsigned long>(kRequestBytes);
        request->version = KSW_DYN_V4_PROTOCOL_VERSION;
        request->flags = profile.flags;
        request->itemCount = static_cast<unsigned long>(profile.items.size());
        request->capabilityGroupCount = static_cast<unsigned long>(profile.capabilityGroups.size());
        request->module = profile.module;
        for (std::size_t index = 0U; index < profile.capabilityGroups.size(); ++index)
        {
            request->capabilityGroups[index] = profile.capabilityGroups[index];
        }
        for (std::size_t index = 0U; index < profile.items.size(); ++index)
        {
            request->items[index] = profile.items[index];
        }

        result.io = deviceIoControl(IOCTL_KSWORD_ARK_APPLY_DYN_PROFILE_V4, requestBuffer.data(), static_cast<unsigned long>(requestBuffer.size()), &result.response, sizeof(result.response));
        markUnsupportedIfNeeded(result, "IOCTL_KSWORD_ARK_APPLY_DYN_PROFILE_V4");
        if (result.io.ok && result.io.bytesReturned < sizeof(KSW_APPLY_DYN_PROFILE_V4_RESPONSE))
        {
            result.io.ok = false;
            result.io.win32Error = ERROR_INSUFFICIENT_BUFFER;
            result.io.message = "DynData v4 apply response too small, bytesReturned=" + std::to_string(result.io.bytesReturned);
        }
        result.io.ntStatus = result.response.status;
        return result;
    }

    DynDataV4ModulesResult DriverClient::queryDynDataV4Modules(const unsigned long maxRows) const
    {
        return queryDynDataV4Rows<DynDataV4ModulesResult, KSW_QUERY_DYN_V4_MODULES_RESPONSE, KSW_DYN_V4_MODULE_STATUS_ENTRY>(*this, IOCTL_KSWORD_ARK_QUERY_DYN_V4_MODULES, maxRows, "IOCTL_KSWORD_ARK_QUERY_DYN_V4_MODULES");
    }

    DynDataV4CapabilityGroupsResult DriverClient::queryDynDataV4CapabilityGroups(const unsigned long maxRows) const
    {
        return queryDynDataV4Rows<DynDataV4CapabilityGroupsResult, KSW_QUERY_DYN_V4_CAPABILITY_GROUPS_RESPONSE, KSW_DYN_V4_CAPABILITY_GROUP_STATUS_ENTRY>(*this, IOCTL_KSWORD_ARK_QUERY_DYN_V4_CAPABILITY_GROUPS, maxRows, "IOCTL_KSWORD_ARK_QUERY_DYN_V4_CAPABILITY_GROUPS");
    }

    DynDataV4MissingItemsResult DriverClient::queryDynDataV4MissingItems(const unsigned long maxRows) const
    {
        return queryDynDataV4Rows<DynDataV4MissingItemsResult, KSW_QUERY_DYN_V4_MISSING_ITEMS_RESPONSE, KSW_DYN_V4_MISSING_ITEM_ENTRY>(*this, IOCTL_KSWORD_ARK_QUERY_DYN_V4_MISSING_ITEMS, maxRows, "IOCTL_KSWORD_ARK_QUERY_DYN_V4_MISSING_ITEMS");
    }

    DynDataV4ItemsResult DriverClient::queryDynDataV4Items(const unsigned long maxRows) const
    {
        return queryDynDataV4Rows<DynDataV4ItemsResult, KSW_QUERY_DYN_V4_ITEMS_RESPONSE, KSW_DYN_V4_ITEM_STATUS_ENTRY>(*this, IOCTL_KSWORD_ARK_QUERY_DYN_V4_ITEMS, maxRows, "IOCTL_KSWORD_ARK_QUERY_DYN_V4_ITEMS");
    }
}

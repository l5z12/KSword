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
        // buildStorageRequest:
        // - Input: Volume path, flags, row budget, and stack depth budget;
        // - Processing: Populate shared Storage request and safely copy optional volume path.
        // - Returns: KSWORD_ARK_STORAGE_AUDIT_REQUEST.
        KSWORD_ARK_STORAGE_AUDIT_REQUEST buildStorageRequest(
            const std::wstring& volumePath,
            const unsigned long flags,
            const unsigned long maxRows,
            const unsigned long maxDepth)
        {
            KSWORD_ARK_STORAGE_AUDIT_REQUEST request{};
            request.version = KSWORD_ARK_STORAGE_PROTOCOL_VERSION;
            request.size = sizeof(request);
            request.flags = flags;
            request.maxRows = maxRows;
            request.maxDepth = maxDepth;
            if (!volumePath.empty())
            {
                copyAuditWideToFixed(request.volumePath, KSWORD_ARK_STORAGE_VOLUME_PATH_CHARS, volumePath);
                request.volumePathLengthChars = static_cast<unsigned short>(std::min<std::size_t>(volumePath.size(), KSWORD_ARK_STORAGE_VOLUME_PATH_CHARS - 1U));
            }
            return request;
        }

        // queryStorageRows:
        // - Input: Any Storage variable-length response/row type and IOCTL;
        // - Processing: Send the request, validate rowSize, and parse the rows.
        // - Returns: the specific Storage result type.
        template <typename TResult, typename TResponse, typename TRow>
        TResult queryStorageRows(
            const DriverClient& client,
            const unsigned long ioctlCode,
            const KSWORD_ARK_STORAGE_AUDIT_REQUEST& request,
            const char* const operationName)
        {
            TResult result{};
            std::vector<std::uint8_t> responseBuffer(kDefaultAuditBufferBytes, 0U);
            result.io = client.deviceIoControl(ioctlCode, const_cast<KSWORD_ARK_STORAGE_AUDIT_REQUEST*>(&request), sizeof(request), responseBuffer.data(), static_cast<unsigned long>(responseBuffer.size()));
            if (!result.io.ok)
            {
                markUnsupportedIfNeeded(result, operationName);
                return result;
            }

            constexpr std::size_t kHeaderSize = sizeof(TResponse) - sizeof(TRow);
            const auto* response = reinterpret_cast<const TResponse*>(responseBuffer.data());
            const std::size_t kParsedCount = validateAuditRows(result.io, kHeaderSize, response->rowSize, sizeof(TRow), response->returnedRows, operationName);
            if (!result.io.ok)
            {
                return result;
            }

            result.version = response->version;
            result.status = response->queryStatus;
            result.entrySize = response->rowSize;
            result.responseFlags = response->responseFlags;
            result.fieldFlags = response->fieldFlags;
            result.totalCount = response->totalRows;
            result.returnedCount = response->returnedRows;
            result.maxRows = response->maxRows;
            result.lastStatus = response->lastStatus;
            result.io.ntStatus = response->lastStatus;
            if constexpr (std::is_same_v<TResult, StorageVolumeStackAuditResult>)
            {
                result.fvevolPresent = response->fvevolPresent;
                result.fvevolPosition = response->fvevolPosition;
            }
            result.rows = parseVariableRows<TRow>(responseBuffer, kHeaderSize, response->rowSize, kParsedCount);
            result.io.message = appendAuditSummary(operationName, result.totalCount, result.returnedCount, result.rows.size(), result.io.bytesReturned);
            return result;
        }
    }

    MinifilterInventoryResult DriverClient::queryMinifilterInventory(const unsigned long flags, const unsigned long maxRows) const
    {
        constexpr const char* kOperationName = "IOCTL_KSWORD_ARK_QUERY_MINIFILTER_INVENTORY";
        MinifilterInventoryResult result{};
        KSWORD_ARK_QUERY_MINIFILTER_INVENTORY_REQUEST request{};
        request.size = sizeof(request);
        request.version = KSWORD_ARK_FILTER_PROTOCOL_VERSION;
        request.flags = flags;
        request.maxRows = maxRows;
        std::vector<std::uint8_t> responseBuffer(kDefaultAuditBufferBytes, 0U);
        result.io = deviceIoControl(IOCTL_KSWORD_ARK_QUERY_MINIFILTER_INVENTORY, &request, sizeof(request), responseBuffer.data(), static_cast<unsigned long>(responseBuffer.size()));
        if (!result.io.ok)
        {
            markUnsupportedIfNeeded(result, kOperationName);
            return result;
        }

        constexpr std::size_t kHeaderSize = sizeof(KSWORD_ARK_QUERY_MINIFILTER_INVENTORY_RESPONSE) - sizeof(KSWORD_ARK_MINIFILTER_INVENTORY_ENTRY);
        const auto* response = reinterpret_cast<const KSWORD_ARK_QUERY_MINIFILTER_INVENTORY_RESPONSE*>(responseBuffer.data());
        const std::size_t kParsedCount = validateAuditRows(result.io, kHeaderSize, response->entrySize, sizeof(KSWORD_ARK_MINIFILTER_INVENTORY_ENTRY), response->returnedCount, kOperationName);
        if (!result.io.ok)
        {
            return result;
        }

        result.version = response->version;
        result.status = response->queryStatus;
        result.totalCount = response->totalCount;
        result.returnedCount = response->returnedCount;
        result.entrySize = response->entrySize;
        result.responseFlags = response->flags;
        result.lastStatus = response->lastStatus;
        result.io.ntStatus = response->lastStatus;
        result.entries = parseVariableRows<KSWORD_ARK_MINIFILTER_INVENTORY_ENTRY>(responseBuffer, kHeaderSize, response->entrySize, kParsedCount);
        result.io.message = appendAuditSummary(kOperationName, result.totalCount, result.returnedCount, result.entries.size(), result.io.bytesReturned);
        return result;
    }

    StorageVolumeStackAuditResult DriverClient::queryVolumeStackAudit(const std::wstring& volumePath, const unsigned long flags, const unsigned long maxRows, const unsigned long maxDepth) const
    {
        const KSWORD_ARK_STORAGE_AUDIT_REQUEST kRequest = buildStorageRequest(volumePath, flags, maxRows, maxDepth);
        return queryStorageRows<StorageVolumeStackAuditResult, KSWORD_ARK_QUERY_VOLUME_STACK_RESPONSE, KSWORD_ARK_VOLUME_STACK_ROW>(*this, IOCTL_KSWORD_ARK_QUERY_VOLUME_STACK_AUDIT, kRequest, "IOCTL_KSWORD_ARK_QUERY_VOLUME_STACK_AUDIT");
    }

    StorageBitlockerFveAuditResult DriverClient::queryBitlockerFveAudit(const std::wstring& volumePath, const unsigned long flags, const unsigned long maxRows, const unsigned long maxDepth) const
    {
        const KSWORD_ARK_STORAGE_AUDIT_REQUEST kRequest = buildStorageRequest(volumePath, flags, maxRows, maxDepth);
        return queryStorageRows<StorageBitlockerFveAuditResult, KSWORD_ARK_QUERY_BITLOCKER_FVE_RESPONSE, KSWORD_ARK_BITLOCKER_FVE_ROW>(*this, IOCTL_KSWORD_ARK_QUERY_BITLOCKER_FVE_AUDIT, kRequest, "IOCTL_KSWORD_ARK_QUERY_BITLOCKER_FVE_AUDIT");
    }

    StorageMountMgrMappingAuditResult DriverClient::queryMountMgrMappingAudit(const std::wstring& volumePath, const unsigned long flags, const unsigned long maxRows, const unsigned long maxDepth) const
    {
        const KSWORD_ARK_STORAGE_AUDIT_REQUEST kRequest = buildStorageRequest(volumePath, flags, maxRows, maxDepth);
        return queryStorageRows<StorageMountMgrMappingAuditResult, KSWORD_ARK_QUERY_MOUNTMGR_MAPPING_RESPONSE, KSWORD_ARK_MOUNTMGR_MAPPING_ROW>(*this, IOCTL_KSWORD_ARK_QUERY_MOUNTMGR_MAPPING_AUDIT, kRequest, "IOCTL_KSWORD_ARK_QUERY_MOUNTMGR_MAPPING_AUDIT");
    }

    StorageFilesystemIntegrityAuditResult DriverClient::queryFilesystemIntegrityAudit(const std::wstring& volumePath, const unsigned long flags, const unsigned long maxRows, const unsigned long maxDepth) const
    {
        const KSWORD_ARK_STORAGE_AUDIT_REQUEST kRequest = buildStorageRequest(volumePath, flags, maxRows, maxDepth);
        return queryStorageRows<StorageFilesystemIntegrityAuditResult, KSWORD_ARK_QUERY_FILESYSTEM_INTEGRITY_RESPONSE, KSWORD_ARK_FILESYSTEM_INTEGRITY_ROW>(*this, IOCTL_KSWORD_ARK_QUERY_FILESYSTEM_INTEGRITY_AUDIT, kRequest, "IOCTL_KSWORD_ARK_QUERY_FILESYSTEM_INTEGRITY_AUDIT");
    }
}

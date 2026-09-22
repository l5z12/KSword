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
#include "ArkDriverNetworkSupport.h"

namespace ksword::ark
{
    using namespace detail::audit;
    using namespace detail::network;
    namespace
    {
        // queryNetworkEndpointAudit:
        // - Input: TCP/UDP IOCTL, flags, row budget, and operation name;
        // - Processing: Send read-only network endpoint query and parse variable-length response.
        // - Return: NetworkEndpointAuditResult.
        NetworkEndpointAuditResult queryNetworkEndpointAudit(
            const DriverClient& client,
            const unsigned long ioctlCode,
            const unsigned long flags,
            const unsigned long maxRows,
            const char* const operationName)
        {
            NetworkEndpointAuditResult result{};
            KSWORD_ARK_NETWORK_AUDIT_QUERY_REQUEST request = buildNetworkRequest(flags, maxRows);
            std::vector<std::uint8_t> responseBuffer(kDefaultAuditBufferBytes, 0U);
            result.io = client.deviceIoControl(ioctlCode, &request, sizeof(request), responseBuffer.data(), static_cast<unsigned long>(responseBuffer.size()));
            if (!result.io.ok)
            {
                markUnsupportedIfNeeded(result, operationName);
                return result;
            }

            constexpr std::size_t kHeaderSize = sizeof(KSWORD_ARK_NETWORK_ENDPOINT_RESPONSE) - sizeof(KSWORD_ARK_NETWORK_ENDPOINT_ROW);
            const auto* response = reinterpret_cast<const KSWORD_ARK_NETWORK_ENDPOINT_RESPONSE*>(responseBuffer.data());
            if (!validateNetworkAuditHeader(result.io, *response, kHeaderSize, operationName))
            {
                return result;
            }
            const std::size_t kParsedCount = validateAuditRows(result.io, kHeaderSize, response->entrySize, sizeof(KSWORD_ARK_NETWORK_ENDPOINT_ROW), response->returnedRowCount, operationName);
            if (!result.io.ok)
            {
                return result;
            }
            if (kParsedCount != static_cast<std::size_t>(response->returnedRowCount))
            {
                result.io.ok = false;
                result.io.win32Error = ERROR_INVALID_DATA;
                result.io.message = std::string(operationName) + " returned rows exceed response bytes";
                return result;
            }

            result.version = response->version;
            result.status = response->status;
            result.flags = response->flags;
            result.totalCount = response->totalRowCount;
            result.returnedCount = response->returnedRowCount;
            result.entrySize = response->entrySize;
            result.sourceFlags = response->sourceFlags;
            result.budgetRows = response->budgetRows;
            result.generation = response->generation;
            result.lastStatus = response->lastStatus;
            result.io.ntStatus = response->lastStatus;
            result.entries = parseVariableRows<KSWORD_ARK_NETWORK_ENDPOINT_ROW>(responseBuffer, kHeaderSize, response->entrySize, kParsedCount);
            const std::uint32_t kExpectedProtocol =
                ioctlCode == IOCTL_KSWORD_ARK_NETWORK_QUERY_TCP_ENDPOINTS
                ? KSWORD_ARK_NETWORK_PROTOCOL_TCP
                : KSWORD_ARK_NETWORK_PROTOCOL_UDP;
            constexpr std::uint32_t kKnownRowFlags =
                KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_PDB_UNAVAILABLE |
                KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_FIELD_MISSING |
                KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_BUDGET_LIMITED |
                KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_OWNER_UNKNOWN |
                KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_MODULE_UNKNOWN;
            constexpr std::uint32_t kKnownSourceFlags =
                KSWORD_ARK_NETWORK_AUDIT_SOURCE_TCPIP_PDB |
                KSWORD_ARK_NETWORK_AUDIT_SOURCE_NETIO_PDB |
                KSWORD_ARK_NETWORK_AUDIT_SOURCE_NDIS_PDB |
                KSWORD_ARK_NETWORK_AUDIT_SOURCE_RUNTIME_STATE;
            for (const KSWORD_ARK_NETWORK_ENDPOINT_ROW& entry : result.entries)
            {
                const bool kKnownFamily =
                    entry.addressFamily == KSWORD_ARK_NETWORK_ADDRESS_FAMILY_UNKNOWN ||
                    entry.addressFamily == KSWORD_ARK_NETWORK_ADDRESS_FAMILY_IPV4 ||
                    entry.addressFamily == KSWORD_ARK_NETWORK_ADDRESS_FAMILY_IPV6;
                if (!kKnownFamily ||
                    entry.protocol != kExpectedProtocol ||
                    (entry.flags & ~kKnownRowFlags) != 0UL ||
                    (entry.sourceFlags & ~kKnownSourceFlags) != 0UL)
                {
                    result.io.ok = false;
                    result.io.win32Error = ERROR_INVALID_DATA;
                    result.io.message = std::string(operationName) + " contains an invalid endpoint row";
                    result.entries.clear();
                    return result;
                }
            }
            finalizeNetworkEndpointCompleteness(result);
            result.io.message = appendNetworkAuditState(
                appendAuditSummary(operationName, result.totalCount, result.returnedCount, result.entries.size(), result.io.bytesReturned),
                result.status,
                result.lastStatus,
                result.sourceFlags,
                result.generation);
            result.io.message += result.partial || result.truncated
                ? ", completeness=partial, truncatedRowsRetained=true"
                : (result.status == KSWORD_ARK_NETWORK_STATUS_APPLIED &&
                   result.totalCount == result.returnedCount
                    ? ", completeness=complete"
                    : ", completeness=unavailable, responseRowsDiscarded=true");
            return result;
        }

        // queryNetworkWfpAudit purpose: Send WFP inventory IOCTL and parse owner/module lines.
        NetworkWfpInventoryResult queryNetworkWfpAudit(
            const DriverClient& client,
            const unsigned long flags,
            const unsigned long maxRows)
        {
            constexpr const char* kOperationName = "IOCTL_KSWORD_ARK_NETWORK_QUERY_WFP_INVENTORY";
            NetworkWfpInventoryResult result{};
            KSWORD_ARK_NETWORK_AUDIT_QUERY_REQUEST request = buildNetworkRequest(flags, maxRows);
            std::vector<std::uint8_t> responseBuffer(kDefaultAuditBufferBytes, 0U);
            result.io = client.deviceIoControl(IOCTL_KSWORD_ARK_NETWORK_QUERY_WFP_INVENTORY, &request, sizeof(request), responseBuffer.data(), static_cast<unsigned long>(responseBuffer.size()));
            if (!result.io.ok)
            {
                markUnsupportedIfNeeded(result, kOperationName);
                return result;
            }

            constexpr std::size_t kHeaderSize = sizeof(KSWORD_ARK_NETWORK_WFP_INVENTORY_RESPONSE) - sizeof(KSWORD_ARK_NETWORK_WFP_INVENTORY_ROW);
            const auto* response = reinterpret_cast<const KSWORD_ARK_NETWORK_WFP_INVENTORY_RESPONSE*>(responseBuffer.data());
            if (!validateNetworkAuditHeader(result.io, *response, kHeaderSize, kOperationName))
            {
                return result;
            }
            const std::size_t kParsedCount = validateAuditRows(result.io, kHeaderSize, response->entrySize, sizeof(KSWORD_ARK_NETWORK_WFP_INVENTORY_ROW), response->returnedRowCount, kOperationName);
            if (!result.io.ok)
            {
                return result;
            }
            if (kParsedCount != static_cast<std::size_t>(response->returnedRowCount))
            {
                result.io.ok = false;
                result.io.win32Error = ERROR_INVALID_DATA;
                result.io.message = std::string(kOperationName) + " returned rows exceed response bytes";
                return result;
            }

            result.version = response->version;
            result.status = response->status;
            result.flags = response->flags;
            result.totalCount = response->totalRowCount;
            result.returnedCount = response->returnedRowCount;
            result.entrySize = response->entrySize;
            result.sourceFlags = response->sourceFlags;
            result.budgetRows = response->budgetRows;
            result.generation = response->generation;
            result.lastStatus = response->lastStatus;
            result.io.ntStatus = response->lastStatus;
            result.entries = parseVariableRows<KSWORD_ARK_NETWORK_WFP_INVENTORY_ROW>(responseBuffer, kHeaderSize, response->entrySize, kParsedCount);
            constexpr std::uint32_t kKnownRowFlags =
                KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_PDB_UNAVAILABLE |
                KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_FIELD_MISSING |
                KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_BUDGET_LIMITED |
                KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_OWNER_UNKNOWN |
                KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_MODULE_UNKNOWN;
            for (const KSWORD_ARK_NETWORK_WFP_INVENTORY_ROW& entry : result.entries)
            {
                if (entry.objectKind < KSWORD_ARK_NETWORK_WFP_OBJECT_PROVIDER ||
                    entry.objectKind > KSWORD_ARK_NETWORK_WFP_OBJECT_CALLOUT ||
                    (entry.flags & ~kKnownRowFlags) != 0UL)
                {
                    result.io.ok = false;
                    result.io.win32Error = ERROR_INVALID_DATA;
                    result.io.message = std::string(kOperationName) + " contains an invalid WFP row";
                    result.entries.clear();
                    return result;
                }
            }
            finalizeNetworkInventoryCompleteness(result);
            result.io.message = appendNetworkAuditState(
                appendAuditSummary(kOperationName, result.totalCount, result.returnedCount, result.entries.size(), result.io.bytesReturned),
                result.status,
                result.lastStatus,
                result.sourceFlags,
                result.generation);
            result.io.message += result.partial || result.truncated
                ? ", completeness=partial, partialRowsRetained=true"
                : (result.status == KSWORD_ARK_NETWORK_STATUS_APPLIED &&
                   result.totalCount == result.returnedCount
                    ? ", completeness=complete"
                    : ", completeness=unavailable, responseRowsDiscarded=true");
            return result;
        }

        // queryNetworkNdisAudit: Send an NDIS chain IOCTL and parse the chain line.
        NetworkNdisChainResult queryNetworkNdisAudit(
            const DriverClient& client,
            const unsigned long flags,
            const unsigned long maxRows)
        {
            constexpr const char* kOperationName = "IOCTL_KSWORD_ARK_NETWORK_QUERY_NDIS_CHAIN";
            NetworkNdisChainResult result{};
            KSWORD_ARK_NETWORK_AUDIT_QUERY_REQUEST request = buildNetworkRequest(flags, maxRows);
            std::vector<std::uint8_t> responseBuffer(kDefaultAuditBufferBytes, 0U);
            result.io = client.deviceIoControl(IOCTL_KSWORD_ARK_NETWORK_QUERY_NDIS_CHAIN, &request, sizeof(request), responseBuffer.data(), static_cast<unsigned long>(responseBuffer.size()));
            if (!result.io.ok)
            {
                markUnsupportedIfNeeded(result, kOperationName);
                return result;
            }

            constexpr std::size_t kHeaderSize = sizeof(KSWORD_ARK_NETWORK_NDIS_CHAIN_RESPONSE) - sizeof(KSWORD_ARK_NETWORK_NDIS_CHAIN_ROW);
            const auto* response = reinterpret_cast<const KSWORD_ARK_NETWORK_NDIS_CHAIN_RESPONSE*>(responseBuffer.data());
            if (!validateNetworkAuditHeader(result.io, *response, kHeaderSize, kOperationName))
            {
                return result;
            }
            const std::size_t kParsedCount = validateAuditRows(result.io, kHeaderSize, response->entrySize, sizeof(KSWORD_ARK_NETWORK_NDIS_CHAIN_ROW), response->returnedRowCount, kOperationName);
            if (!result.io.ok)
            {
                return result;
            }
            if (kParsedCount != static_cast<std::size_t>(response->returnedRowCount))
            {
                result.io.ok = false;
                result.io.win32Error = ERROR_INVALID_DATA;
                result.io.message = std::string(kOperationName) + " returned rows exceed response bytes";
                return result;
            }

            result.version = response->version;
            result.status = response->status;
            result.flags = response->flags;
            result.totalCount = response->totalRowCount;
            result.returnedCount = response->returnedRowCount;
            result.entrySize = response->entrySize;
            result.sourceFlags = response->sourceFlags;
            result.budgetRows = response->budgetRows;
            result.generation = response->generation;
            result.lastStatus = response->lastStatus;
            result.io.ntStatus = response->lastStatus;
            result.entries = parseVariableRows<KSWORD_ARK_NETWORK_NDIS_CHAIN_ROW>(responseBuffer, kHeaderSize, response->entrySize, kParsedCount);
            constexpr std::uint32_t kKnownRowFlags =
                KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_PDB_UNAVAILABLE |
                KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_FIELD_MISSING |
                KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_BUDGET_LIMITED |
                KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_OWNER_UNKNOWN |
                KSWORD_ARK_NETWORK_AUDIT_ROW_FLAG_MODULE_UNKNOWN;
            for (const KSWORD_ARK_NETWORK_NDIS_CHAIN_ROW& entry : result.entries)
            {
                if (entry.objectKind > KSWORD_ARK_NETWORK_NDIS_OBJECT_BINDING ||
                    (entry.flags & ~kKnownRowFlags) != 0UL)
                {
                    result.io.ok = false;
                    result.io.win32Error = ERROR_INVALID_DATA;
                    result.io.message = std::string(kOperationName) + " contains an invalid NDIS row";
                    result.entries.clear();
                    return result;
                }
            }
            finalizeNetworkInventoryCompleteness(result);
            result.io.message = appendNetworkAuditState(
                appendAuditSummary(kOperationName, result.totalCount, result.returnedCount, result.entries.size(), result.io.bytesReturned),
                result.status,
                result.lastStatus,
                result.sourceFlags,
                result.generation);
            result.io.message += result.partial || result.truncated
                ? ", completeness=partial, partialRowsRetained=true"
                : (result.status == KSWORD_ARK_NETWORK_STATUS_APPLIED &&
                   result.totalCount == result.returnedCount
                    ? ", completeness=complete"
                    : ", completeness=unavailable, responseRowsDiscarded=true");
            return result;
        }
    }

    NetworkEndpointAuditResult DriverClient::queryNetworkTcpEndpoints(const unsigned long flags, const unsigned long maxRows) const
    {
        return queryNetworkEndpointAudit(*this, IOCTL_KSWORD_ARK_NETWORK_QUERY_TCP_ENDPOINTS, flags, maxRows, "IOCTL_KSWORD_ARK_NETWORK_QUERY_TCP_ENDPOINTS");
    }

    NetworkEndpointAuditResult DriverClient::queryNetworkUdpEndpoints(const unsigned long flags, const unsigned long maxRows) const
    {
        return queryNetworkEndpointAudit(*this, IOCTL_KSWORD_ARK_NETWORK_QUERY_UDP_ENDPOINTS, flags, maxRows, "IOCTL_KSWORD_ARK_NETWORK_QUERY_UDP_ENDPOINTS");
    }

    NetworkWfpInventoryResult DriverClient::queryNetworkWfpInventory(const unsigned long flags, const unsigned long maxRows) const
    {
        return queryNetworkWfpAudit(*this, flags, maxRows);
    }

    NetworkNdisChainResult DriverClient::queryNetworkNdisChain(const unsigned long flags, const unsigned long maxRows) const
    {
        return queryNetworkNdisAudit(*this, flags, maxRows);
    }
}

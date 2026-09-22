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
    CidTableAuditResult DriverClient::enumCidTable(const unsigned long flags, const unsigned long maxEntries, const unsigned long maxVisitCount, const unsigned long startCid, const unsigned long endCid) const
    {
        constexpr const char* kOperationName = "IOCTL_KSWORD_ARK_ENUM_CID_TABLE";
        CidTableAuditResult result{};
        KSWORD_ARK_ENUM_CID_TABLE_REQUEST request{};
        request.version = KSWORD_ARK_KERNEL_OBJECT_PROTOCOL_VERSION;
        request.flags = flags;
        request.maxEntries = maxEntries;
        request.maxVisitCount = maxVisitCount;
        request.startCid = startCid;
        request.endCid = endCid;
        std::vector<std::uint8_t> responseBuffer(kDefaultAuditBufferBytes, 0U);
        result.io = deviceIoControl(IOCTL_KSWORD_ARK_ENUM_CID_TABLE, &request, sizeof(request), responseBuffer.data(), static_cast<unsigned long>(responseBuffer.size()));
        if (!result.io.ok)
        {
            markUnsupportedIfNeeded(result, kOperationName);
            return result;
        }

        constexpr std::size_t kHeaderSize = sizeof(KSWORD_ARK_ENUM_CID_TABLE_RESPONSE) - sizeof(KSWORD_ARK_CID_TABLE_ENTRY);
        const auto* response = reinterpret_cast<const KSWORD_ARK_ENUM_CID_TABLE_RESPONSE*>(responseBuffer.data());
        const std::size_t kParsedCount = validateAuditRows(result.io, kHeaderSize, response->entrySize, sizeof(KSWORD_ARK_CID_TABLE_ENTRY), response->returnedCount, kOperationName);
        if (!result.io.ok)
        {
            return result;
        }

        result.version = response->version;
        result.status = response->status;
        result.totalCount = response->totalCount;
        result.returnedCount = response->returnedCount;
        result.entrySize = response->entrySize;
        result.flags = response->flags;
        result.visitedCount = response->visitedCount;
        result.maxVisitCount = response->maxVisitCount;
        result.lastStatus = response->lastStatus;
        result.pspCidTableAddress = response->pspCidTableAddress;
        result.dynDataCapabilityMask = response->dynDataCapabilityMask;
        result.htTableCodeOffset = response->htTableCodeOffset;
        result.hteLowValueOffset = response->hteLowValueOffset;
        result.io.ntStatus = response->lastStatus;
        result.entries = parseVariableRows<KSWORD_ARK_CID_TABLE_ENTRY>(responseBuffer, kHeaderSize, response->entrySize, kParsedCount);
        result.io.message = appendAuditSummary(kOperationName, result.totalCount, result.returnedCount, result.entries.size(), result.io.bytesReturned);
        return result;
    }

    ObjectTypeTableAuditResult DriverClient::enumObjectTypeTable(const unsigned long flags, const unsigned long maxEntries, const unsigned long startIndex) const
    {
        constexpr const char* kOperationName = "IOCTL_KSWORD_ARK_ENUM_OBJECT_TYPE_TABLE";
        ObjectTypeTableAuditResult result{};
        KSWORD_ARK_ENUM_OBJECT_TYPE_TABLE_REQUEST request{};
        request.version = KSWORD_ARK_KERNEL_OBJECT_PROTOCOL_VERSION;
        request.flags = flags;
        request.startIndex = startIndex;
        request.maxEntries = maxEntries;

        std::vector<std::uint8_t> responseBuffer(kDefaultAuditBufferBytes, 0U);
        result.io = deviceIoControl(
            IOCTL_KSWORD_ARK_ENUM_OBJECT_TYPE_TABLE,
            &request,
            sizeof(request),
            responseBuffer.data(),
            static_cast<unsigned long>(responseBuffer.size()));
        if (!result.io.ok)
        {
            markUnsupportedIfNeeded(result, kOperationName);
            return result;
        }

        constexpr std::size_t kHeaderSize =
            sizeof(KSWORD_ARK_ENUM_OBJECT_TYPE_TABLE_RESPONSE) -
            sizeof(KSWORD_ARK_OBJECT_TYPE_TABLE_ENTRY);
        const auto* response =
            reinterpret_cast<const KSWORD_ARK_ENUM_OBJECT_TYPE_TABLE_RESPONSE*>(
                responseBuffer.data());
        const std::size_t kParsedCount = validateAuditRows(
            result.io,
            kHeaderSize,
            response->entrySize,
            sizeof(KSWORD_ARK_OBJECT_TYPE_TABLE_ENTRY),
            response->returnedCount,
            kOperationName);
        if (!result.io.ok)
        {
            return result;
        }

        result.version = response->version;
        result.status = response->status;
        result.totalCount = response->totalCount;
        result.returnedCount = response->returnedCount;
        result.entrySize = response->entrySize;
        result.flags = response->flags;
        result.lastStatus = response->lastStatus;
        result.nextIndex = response->nextIndex;
        result.tableAddress = response->tableAddress;
        result.dynDataCapabilityMask = response->dynDataCapabilityMask;
        result.snapshotHash = response->snapshotHash;
        result.otNameOffset = response->otNameOffset;
        result.otIndexOffset = response->otIndexOffset;
        result.io.ntStatus = response->lastStatus;
        result.entries = parseVariableRows<KSWORD_ARK_OBJECT_TYPE_TABLE_ENTRY>(
            responseBuffer,
            kHeaderSize,
            response->entrySize,
            kParsedCount);
        result.io.message = appendAuditSummary(
            kOperationName,
            result.totalCount,
            result.returnedCount,
            result.entries.size(),
            result.io.bytesReturned);
        return result;
    }

    KernelObjectSummaryAuditResult DriverClient::queryKernelObjectSummary(const unsigned long targetKind, const unsigned long cidValue, const std::uint64_t expectedObjectAddress, const unsigned long flags) const
    {
        KernelObjectSummaryAuditResult result{};
        KSWORD_ARK_QUERY_KERNEL_OBJECT_SUMMARY_REQUEST request{};
        request.version = KSWORD_ARK_KERNEL_OBJECT_PROTOCOL_VERSION;
        request.flags = flags;
        request.targetKind = targetKind;
        request.cidValue = cidValue;
        request.expectedObjectAddress = expectedObjectAddress;
        result.io = queryFixedAudit(*this, IOCTL_KSWORD_ARK_QUERY_KERNEL_OBJECT_SUMMARY, &request, result.response, "IOCTL_KSWORD_ARK_QUERY_KERNEL_OBJECT_SUMMARY");
        markUnsupportedIfNeeded(result, "IOCTL_KSWORD_ARK_QUERY_KERNEL_OBJECT_SUMMARY");
        result.io.ntStatus = result.response.lookupStatus;
        return result;
    }

    IpcSummaryAuditResult DriverClient::queryIpcSummary(const unsigned long processId, const std::uint64_t handleValue, const unsigned long flags, const unsigned long maxEntries) const
    {
        IpcSummaryAuditResult result{};
        KSWORD_ARK_QUERY_IPC_SUMMARY_REQUEST request{};
        request.version = KSWORD_ARK_KERNEL_OBJECT_PROTOCOL_VERSION;
        request.flags = flags;
        request.processId = processId;
        request.handleValue = handleValue;
        request.maxEntries = maxEntries;
        result.io = queryFixedAudit(*this, IOCTL_KSWORD_ARK_QUERY_IPC_SUMMARY, &request, result.response, "IOCTL_KSWORD_ARK_QUERY_IPC_SUMMARY");
        markUnsupportedIfNeeded(result, "IOCTL_KSWORD_ARK_QUERY_IPC_SUMMARY");
        result.io.ntStatus = result.response.lastStatus;
        return result;
    }
}

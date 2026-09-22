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
    ProcessIntegrityResult DriverClient::setProcessIntegrity(
        const std::uint32_t processId,
        const unsigned long integrityRid) const
    {
        // Input: Target PID and Mandatory Label RID.
        // Handles: Constructs a fixed R0 protocol packet; the driver first writes TokenIntegrityLevel via
        // ZwOpenProcessTokenEx/ZwSetInformationToken. If this fails, the R0 DynData/PDB private Token field path serves as a fallback.
        // Returns: ProcessIntegrityResult. io.ok indicates successful communication; status/lastStatus represent R0 semantic results.
        ProcessIntegrityResult integrityResult{};
        KSWORD_ARK_SET_PROCESS_INTEGRITY_REQUEST request{};
        KSWORD_ARK_SET_PROCESS_INTEGRITY_RESPONSE response{};
        request.size = static_cast<unsigned long>(sizeof(request));
        request.version = KSWORD_ARK_PROCESS_INTEGRITY_PROTOCOL_VERSION;
        request.processId = processId;
        request.integrityRid = integrityRid;
        request.flags = KSWORD_ARK_PROCESS_INTEGRITY_FLAG_UI_CONFIRMED;

        integrityResult.io = deviceIoControl(
            IOCTL_KSWORD_ARK_SET_PROCESS_INTEGRITY,
            &request,
            static_cast<unsigned long>(sizeof(request)),
            &response,
            static_cast<unsigned long>(sizeof(response)));
        if (!integrityResult.io.ok)
        {
            integrityResult.unsupported = isUnsupportedIoctlError(integrityResult.io.win32Error);
            integrityResult.io.message = integrityResult.unsupported
                ? "IOCTL_KSWORD_ARK_SET_PROCESS_INTEGRITY unsupported or driver version is too old"
                : "DeviceIoControl(IOCTL_KSWORD_ARK_SET_PROCESS_INTEGRITY) failed, error=" +
                    std::to_string(integrityResult.io.win32Error);
            return integrityResult;
        }
        if (integrityResult.io.bytesReturned < sizeof(response))
        {
            integrityResult.io.ok = false;
            integrityResult.io.message =
                "process-integrity response too small, bytesReturned=" +
                std::to_string(integrityResult.io.bytesReturned);
            return integrityResult;
        }

        integrityResult.version = static_cast<std::uint32_t>(response.version);
        integrityResult.processId = static_cast<std::uint32_t>(response.processId);
        integrityResult.integrityRid = static_cast<std::uint32_t>(response.integrityRid);
        integrityResult.status = static_cast<std::uint32_t>(response.status);
        integrityResult.lastStatus = static_cast<long>(response.lastStatus);
        integrityResult.io.ntStatus = integrityResult.lastStatus;

        std::ostringstream stream;
        stream << "pid=" << integrityResult.processId
            << ", rid=0x" << std::hex << std::uppercase << integrityResult.integrityRid
            << std::dec << ", status=" << integrityResult.status
            << ", lastStatus=0x" << std::hex << static_cast<unsigned long>(integrityResult.lastStatus)
            << std::dec << ", bytesReturned=" << integrityResult.io.bytesReturned;
        integrityResult.io.message = stream.str();
        return integrityResult;
    }

    ProcessTokenPrivilegeResult DriverClient::queryProcessTokenPrivileges(
        const std::uint32_t processId,
        const std::uint64_t expectedCreateTime100ns) const
    {
        // Input: Target PID and optional creation time.
        // Processing: Issue a QUERY request and convert the fixed LUID/attribute array into a C++ result.
        // Returns: result distinguishing old drivers, communication failures, truncated snapshots, and complete snapshots.
        ProcessTokenPrivilegeResult queryResult{};
        KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_REQUEST request{};
        KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_RESPONSE response{};
        request.size = static_cast<unsigned long>(sizeof(request));
        request.version = KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_PROTOCOL_VERSION;
        request.operation = KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_OPERATION_QUERY;
        request.processId = processId;
        request.expectedCreateTime100ns = expectedCreateTime100ns;

        queryResult.io = deviceIoControl(
            IOCTL_KSWORD_ARK_PROCESS_TOKEN_PRIVILEGES,
            &request,
            static_cast<unsigned long>(sizeof(request)),
            &response,
            static_cast<unsigned long>(sizeof(response)));
        if (!queryResult.io.ok)
        {
            queryResult.unsupported = isUnsupportedIoctlError(queryResult.io.win32Error);
            queryResult.io.message = queryResult.unsupported
                ? "IOCTL_KSWORD_ARK_PROCESS_TOKEN_PRIVILEGES unsupported or driver version is too old"
                : "DeviceIoControl(IOCTL_KSWORD_ARK_PROCESS_TOKEN_PRIVILEGES query) failed, error=" +
                    std::to_string(queryResult.io.win32Error);
            return queryResult;
        }
        if (queryResult.io.bytesReturned < sizeof(response))
        {
            queryResult.io.ok = false;
            queryResult.io.message =
                "process-token privilege query response too small, bytesReturned=" +
                std::to_string(queryResult.io.bytesReturned);
            return queryResult;
        }
        if (response.size != sizeof(response) ||
            response.version != KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_PROTOCOL_VERSION ||
            response.operation != KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_OPERATION_QUERY ||
            response.processId != processId ||
            response.entryCount > KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_MAX_ENTRIES ||
            response.status < KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_STATUS_OK ||
            response.status > KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_STATUS_FAILED ||
            ((response.status == KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_STATUS_OK ||
              response.status == KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_STATUS_PARTIAL) &&
             (response.processCreateTime100ns == 0U ||
              (expectedCreateTime100ns != 0U &&
               response.processCreateTime100ns != expectedCreateTime100ns))))
        {
            queryResult.io.ok = false;
            queryResult.io.win32Error = ERROR_INVALID_DATA;
            queryResult.io.message = "process-token privilege query response header is invalid";
            return queryResult;
        }

        queryResult.version = static_cast<std::uint32_t>(response.version);
        queryResult.operation = static_cast<std::uint32_t>(response.operation);
        queryResult.processId = static_cast<std::uint32_t>(response.processId);
        queryResult.status = static_cast<std::uint32_t>(response.status);
        queryResult.lastStatus = static_cast<long>(response.lastStatus);
        queryResult.processCreateTime100ns =
            static_cast<std::uint64_t>(response.processCreateTime100ns);
        const std::uint32_t kEntryCount = std::min<std::uint32_t>(
            static_cast<std::uint32_t>(response.entryCount),
            KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_MAX_ENTRIES);
        queryResult.entries.reserve(kEntryCount);
        for (std::uint32_t entryIndex = 0; entryIndex < kEntryCount; ++entryIndex)
        {
            ProcessTokenPrivilegeEntry entry{};
            entry.luidLowPart = static_cast<std::uint32_t>(response.entries[entryIndex].luidLowPart);
            entry.luidHighPart = static_cast<std::int32_t>(response.entries[entryIndex].luidHighPart);
            entry.attributes = static_cast<std::uint32_t>(response.entries[entryIndex].attributes);
            entry.action = static_cast<std::uint32_t>(response.entries[entryIndex].action);
            queryResult.entries.push_back(entry);
        }
        queryResult.io.ntStatus = queryResult.lastStatus;

        std::ostringstream stream;
        stream << "pid=" << queryResult.processId
            << ", operation=query, status=" << queryResult.status
            << ", entries=" << queryResult.entries.size()
            << ", lastStatus=0x" << std::hex << static_cast<unsigned long>(queryResult.lastStatus)
            << std::dec << ", bytesReturned=" << queryResult.io.bytesReturned;
        queryResult.io.message = stream.str();
        return queryResult;
    }

    ProcessTokenPrivilegeResult DriverClient::adjustProcessTokenPrivileges(
        const std::uint32_t processId,
        const std::uint64_t expectedCreateTime100ns,
        const std::vector<ProcessTokenPrivilegeEntry>& edits,
        const bool allowRemove) const
    {
        // Input: Stable process identity, adjusted items with resolved LUIDs, and removed privileges.
        // Handling: Enforce local constraint protocol limits/actions, then issue confirmation-gated ADJUST request.
        // Returns a result containing appliedCount/failedIndex, allowing the caller to explicitly indicate partial success.
        ProcessTokenPrivilegeResult adjustResult{};
        if (processId <= 4U || expectedCreateTime100ns == 0U
            || edits.empty()
            || edits.size() > KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_MAX_ENTRIES)
        {
            adjustResult.io.win32Error = ERROR_INVALID_PARAMETER;
            adjustResult.io.message = "process-token privilege edit count is invalid";
            return adjustResult;
        }

        KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_REQUEST request{};
        KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_RESPONSE response{};
        request.size = static_cast<unsigned long>(sizeof(request));
        request.version = KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_PROTOCOL_VERSION;
        request.operation = KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_OPERATION_ADJUST;
        request.processId = processId;
        request.flags = KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_FLAG_UI_CONFIRMED |
            (allowRemove ? KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_FLAG_ALLOW_REMOVE : 0UL);
        request.entryCount = static_cast<unsigned long>(edits.size());
        request.expectedCreateTime100ns = expectedCreateTime100ns;
        request.confirmationToken = KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_CONFIRMATION_TOKEN;

        for (std::size_t entryIndex = 0; entryIndex < edits.size(); ++entryIndex)
        {
            const ProcessTokenPrivilegeEntry& sourceEntry = edits[entryIndex];
            const bool kValidAction =
                sourceEntry.action == KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_ACTION_ENABLE ||
                sourceEntry.action == KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_ACTION_DISABLE ||
                sourceEntry.action == KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_ACTION_REMOVE;
            if (!kValidAction ||
                (sourceEntry.action == KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_ACTION_REMOVE && !allowRemove))
            {
                adjustResult.io.win32Error = ERROR_INVALID_PARAMETER;
                adjustResult.io.message = "process-token privilege edit action is invalid";
                return adjustResult;
            }
            request.entries[entryIndex].luidLowPart = sourceEntry.luidLowPart;
            request.entries[entryIndex].luidHighPart = sourceEntry.luidHighPart;
            request.entries[entryIndex].attributes = sourceEntry.attributes;
            request.entries[entryIndex].action = sourceEntry.action;
        }

        adjustResult.io = deviceIoControl(
            IOCTL_KSWORD_ARK_PROCESS_TOKEN_PRIVILEGES,
            &request,
            static_cast<unsigned long>(sizeof(request)),
            &response,
            static_cast<unsigned long>(sizeof(response)));
        if (!adjustResult.io.ok)
        {
            adjustResult.unsupported = isUnsupportedIoctlError(adjustResult.io.win32Error);
            adjustResult.io.message = adjustResult.unsupported
                ? "IOCTL_KSWORD_ARK_PROCESS_TOKEN_PRIVILEGES unsupported or driver version is too old"
                : "DeviceIoControl(IOCTL_KSWORD_ARK_PROCESS_TOKEN_PRIVILEGES adjust) failed, error=" +
                    std::to_string(adjustResult.io.win32Error);
            return adjustResult;
        }
        if (adjustResult.io.bytesReturned < sizeof(response))
        {
            adjustResult.io.ok = false;
            adjustResult.io.message =
                "process-token privilege adjust response too small, bytesReturned=" +
                std::to_string(adjustResult.io.bytesReturned);
            return adjustResult;
        }
        if (response.size != sizeof(response) ||
            response.version != KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_PROTOCOL_VERSION ||
            response.operation != KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_OPERATION_ADJUST ||
            response.processId != processId ||
            response.requestedCount != static_cast<unsigned long>(edits.size()) ||
            response.appliedCount > response.requestedCount ||
            response.status < KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_STATUS_OK ||
            response.status > KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_STATUS_FAILED ||
            (response.failedIndex != KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_FAILED_INDEX_NONE &&
             response.failedIndex >= response.requestedCount) ||
            (response.status == KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_STATUS_OK &&
             (response.appliedCount != response.requestedCount ||
              response.failedIndex != KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_FAILED_INDEX_NONE)) ||
            (response.status == KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_STATUS_PARTIAL &&
             (response.appliedCount == 0U ||
              response.appliedCount >= response.requestedCount ||
              response.failedIndex != response.appliedCount)) ||
            (response.status == KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_STATUS_FAILED &&
             response.appliedCount != 0U) ||
            ((response.status == KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_STATUS_OK ||
              response.status == KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_STATUS_PARTIAL) &&
             response.processCreateTime100ns != expectedCreateTime100ns) ||
            (response.processCreateTime100ns != 0U &&
             response.processCreateTime100ns != expectedCreateTime100ns))
        {
            adjustResult.io.ok = false;
            adjustResult.io.win32Error = ERROR_INVALID_DATA;
            adjustResult.io.message = "process-token privilege adjust response header is invalid";
            return adjustResult;
        }

        adjustResult.version = static_cast<std::uint32_t>(response.version);
        adjustResult.operation = static_cast<std::uint32_t>(response.operation);
        adjustResult.processId = static_cast<std::uint32_t>(response.processId);
        adjustResult.status = static_cast<std::uint32_t>(response.status);
        adjustResult.requestedCount = static_cast<std::uint32_t>(response.requestedCount);
        adjustResult.appliedCount = static_cast<std::uint32_t>(response.appliedCount);
        adjustResult.failedIndex = static_cast<std::uint32_t>(response.failedIndex);
        adjustResult.lastStatus = static_cast<long>(response.lastStatus);
        adjustResult.processCreateTime100ns =
            static_cast<std::uint64_t>(response.processCreateTime100ns);
        adjustResult.io.ntStatus = adjustResult.lastStatus;

        std::ostringstream stream;
        stream << "pid=" << adjustResult.processId
            << ", operation=adjust, status=" << adjustResult.status
            << ", requested=" << adjustResult.requestedCount
            << ", applied=" << adjustResult.appliedCount
            << ", failedIndex=" << adjustResult.failedIndex
            << ", lastStatus=0x" << std::hex << static_cast<unsigned long>(adjustResult.lastStatus)
            << std::dec << ", bytesReturned=" << adjustResult.io.bytesReturned;
        adjustResult.io.message = stream.str();
        return adjustResult;
    }

    ProcessTokenPrivilegeQueryResult DriverClient::queryProcessTokenPrivileges(
        const std::uint32_t processId,
        DriverHandle* const existingHandle) const
    {
        ProcessTokenPrivilegeQueryResult result{};
        KSWORD_ARK_QUERY_PROCESS_TOKEN_PRIVILEGES_REQUEST request{};
        constexpr std::size_t kResponseHeaderSize =
            KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_RESPONSE_HEADER_SIZE;
        constexpr std::size_t kResponseCapacity =
            kResponseHeaderSize +
            (KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_MAX_ENTRIES *
             sizeof(KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_ENTRY));
        std::vector<std::uint8_t> responseBuffer(kResponseCapacity, 0U);

        request.size = static_cast<unsigned long>(sizeof(request));
        request.version = KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_PROTOCOL_VERSION;
        request.processId = processId;

        result.io = deviceIoControl(
            IOCTL_KSWORD_ARK_QUERY_PROCESS_TOKEN_PRIVILEGES,
            &request,
            static_cast<unsigned long>(sizeof(request)),
            responseBuffer.data(),
            static_cast<unsigned long>(responseBuffer.size()),
            existingHandle);
        if (!result.io.ok)
        {
            result.unsupported = isUnsupportedIoctlError(result.io.win32Error);
            result.io.message = "IOCTL_KSWORD_ARK_QUERY_PROCESS_TOKEN_PRIVILEGES failed";
            return result;
        }
        if (result.io.bytesReturned < kResponseHeaderSize)
        {
            result.io.ok = false;
            result.io.win32Error = ERROR_INVALID_DATA;
            result.io.message = "process-token-privilege query response too small";
            return result;
        }

        const auto* response = reinterpret_cast<
            const KSWORD_ARK_QUERY_PROCESS_TOKEN_PRIVILEGES_RESPONSE*>(
                responseBuffer.data());
        const std::size_t kRequiredBytes = kResponseHeaderSize +
            (static_cast<std::size_t>(response->returnedCount) *
             sizeof(KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_ENTRY));
        if (response->version != KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_PROTOCOL_VERSION ||
            response->entrySize != sizeof(KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_ENTRY) ||
            response->returnedCount > KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_MAX_ENTRIES ||
            response->size < kRequiredBytes ||
            result.io.bytesReturned < kRequiredBytes)
        {
            result.io.ok = false;
            result.io.win32Error = ERROR_INVALID_DATA;
            result.io.message = "process-token-privilege query response invalid";
            return result;
        }

        result.version = static_cast<std::uint32_t>(response->version);
        result.processId = static_cast<std::uint32_t>(response->processId);
        result.status = static_cast<std::uint32_t>(response->status);
        result.totalCount = static_cast<std::uint32_t>(response->totalCount);
        result.returnedCount = static_cast<std::uint32_t>(response->returnedCount);
        result.lastStatus = static_cast<long>(response->lastStatus);
        result.io.ntStatus = result.lastStatus;
        result.entries.reserve(result.returnedCount);
        for (std::uint32_t index = 0; index < result.returnedCount; ++index)
        {
            ProcessTokenPrivilegeEntry entry{};
            entry.luidLowPart = static_cast<std::uint32_t>(response->entries[index].luidLowPart);
            entry.luidHighPart = static_cast<std::int32_t>(response->entries[index].luidHighPart);
            entry.attributes = static_cast<std::uint32_t>(response->entries[index].attributes);
            result.entries.push_back(entry);
        }

        std::ostringstream stream;
        stream << "pid=" << result.processId
            << ", status=" << result.status
            << ", count=" << result.returnedCount << "/" << result.totalCount
            << ", lastStatus=0x" << std::hex
            << static_cast<unsigned long>(result.lastStatus);
        result.io.message = stream.str();
        return result;
    }

    ProcessTokenPrivilegeAdjustResult DriverClient::adjustProcessTokenPrivilege(
        const std::uint32_t processId,
        const std::uint32_t luidLowPart,
        const std::int32_t luidHighPart,
        const bool enabled,
        DriverHandle* const existingHandle) const
    {
        ProcessTokenPrivilegeAdjustResult result{};
        KSWORD_ARK_ADJUST_PROCESS_TOKEN_PRIVILEGE_REQUEST request{};
        KSWORD_ARK_ADJUST_PROCESS_TOKEN_PRIVILEGE_RESPONSE response{};

        request.size = static_cast<unsigned long>(sizeof(request));
        request.version = KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_PROTOCOL_VERSION;
        request.processId = processId;
        request.luidLowPart = luidLowPart;
        request.luidHighPart = luidHighPart;
        request.action = enabled
            ? KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_ACTION_ENABLE
            : KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_ACTION_DISABLE;
        request.flags = KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_FLAG_UI_CONFIRMED;

        result.io = deviceIoControl(
            IOCTL_KSWORD_ARK_ADJUST_PROCESS_TOKEN_PRIVILEGE,
            &request,
            static_cast<unsigned long>(sizeof(request)),
            &response,
            static_cast<unsigned long>(sizeof(response)),
            existingHandle);
        if (!result.io.ok)
        {
            result.unsupported = isUnsupportedIoctlError(result.io.win32Error);
            result.io.message = "IOCTL_KSWORD_ARK_ADJUST_PROCESS_TOKEN_PRIVILEGE failed";
            return result;
        }
        if (result.io.bytesReturned < sizeof(response) ||
            response.size != sizeof(response) ||
            response.version != KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_PROTOCOL_VERSION)
        {
            result.io.ok = false;
            result.io.win32Error = ERROR_INVALID_DATA;
            result.io.message = "process-token-privilege adjust response invalid";
            return result;
        }

        result.version = static_cast<std::uint32_t>(response.version);
        result.processId = static_cast<std::uint32_t>(response.processId);
        result.luidLowPart = static_cast<std::uint32_t>(response.luidLowPart);
        result.luidHighPart = static_cast<std::int32_t>(response.luidHighPart);
        result.action = static_cast<std::uint32_t>(response.action);
        result.status = static_cast<std::uint32_t>(response.status);
        result.lastStatus = static_cast<long>(response.lastStatus);
        result.io.ntStatus = result.lastStatus;

        std::ostringstream stream;
        stream << "pid=" << result.processId
            << ", luid=" << result.luidHighPart << ":" << result.luidLowPart
            << ", action=" << result.action
            << ", status=" << result.status
            << ", lastStatus=0x" << std::hex
            << static_cast<unsigned long>(result.lastStatus);
        result.io.message = stream.str();
        return result;
    }
}

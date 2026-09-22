#include "ArkDriverClient.h"
#include "ArkDriverResponseSupport.h"

#include <cstddef>
#include <cstdint>
#include <limits>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace ksword::ark
{
    namespace
    {
        constexpr std::size_t kWorkQueueHeaderSize =
            KSWORD_ARK_ENUM_WORK_QUEUE_RESPONSE_HEADER_SIZE;


        std::string boundedWorkQueueAnsi(
            const char* const text,
            const std::size_t capacity)
        {
            if (text == nullptr || capacity == 0U)
            {
                return {};
            }
            std::size_t length = 0U;
            while (length < capacity && text[length] != '\0')
            {
                ++length;
            }
            return std::string(text, text + length);
        }

        void rejectWorkQueueResponse(
            WorkQueueEnumResult* const result,
            const std::string& message)
        {
            if (result == nullptr)
            {
                return;
            }
            result->io.ok = false;
            result->io.win32Error = ERROR_INVALID_DATA;
            result->io.message = message;
            result->entries.clear();
        }

        bool workQueueHeaderIsConsistent(
            const KSWORD_ARK_ENUM_WORK_QUEUE_RESPONSE& header)
        {
            if (header.size != kWorkQueueHeaderSize ||
                header.version != KSWORD_ARK_WORK_QUEUE_PROTOCOL_VERSION ||
                header.queryStatus > KSWORD_ARK_WORK_QUEUE_QUERY_STATUS_READ_FAILED ||
                (header.statusFlags & ~KSWORD_ARK_WORK_QUEUE_STATUS_VALID_MASK) != 0UL ||
                header.entrySize != sizeof(KSWORD_ARK_WORK_QUEUE_ENTRY) ||
                header.nodeCount > KSWORD_ARK_WORK_QUEUE_MAX_NODES ||
                header.returnedCount > header.totalCount ||
                header.reserved0 != 0UL ||
                header.reserved1 != 0UL ||
                header.reserved2 != 0UL)
            {
                return false;
            }

            const bool kIdentityAndLayout =
                (header.statusFlags &
                 (KSWORD_ARK_WORK_QUEUE_STATUS_IDENTITY_MATCHED |
                  KSWORD_ARK_WORK_QUEUE_STATUS_LAYOUT_VALIDATED)) ==
                (KSWORD_ARK_WORK_QUEUE_STATUS_IDENTITY_MATCHED |
                 KSWORD_ARK_WORK_QUEUE_STATUS_LAYOUT_VALIDATED);
            if ((header.queryStatus == KSWORD_ARK_WORK_QUEUE_QUERY_STATUS_OK ||
                 header.queryStatus == KSWORD_ARK_WORK_QUEUE_QUERY_STATUS_PARTIAL) &&
                !kIdentityAndLayout)
            {
                return false;
            }
            if (header.queryStatus == KSWORD_ARK_WORK_QUEUE_QUERY_STATUS_OK &&
                (header.statusFlags & KSWORD_ARK_WORK_QUEUE_STATUS_PARTIAL) != 0UL)
            {
                return false;
            }
            if (header.queryStatus == KSWORD_ARK_WORK_QUEUE_QUERY_STATUS_PARTIAL &&
                (header.statusFlags & KSWORD_ARK_WORK_QUEUE_STATUS_PARTIAL) == 0UL)
            {
                return false;
            }
            if (header.queryStatus != KSWORD_ARK_WORK_QUEUE_QUERY_STATUS_OK &&
                header.queryStatus != KSWORD_ARK_WORK_QUEUE_QUERY_STATUS_PARTIAL &&
                (header.returnedCount != 0UL || header.totalCount != 0UL))
            {
                return false;
            }
            return true;
        }

        bool workQueueEntryIsConsistent(
            const KSWORD_ARK_WORK_QUEUE_ENTRY& entry,
            const unsigned long nodeCount)
        {
            if (entry.size != sizeof(KSWORD_ARK_WORK_QUEUE_ENTRY) ||
                (entry.rowKind != KSWORD_ARK_WORK_QUEUE_ROW_WORK_ITEM &&
                 entry.rowKind != KSWORD_ARK_WORK_QUEUE_ROW_WORKER_THREAD) ||
                entry.queueType < KSWORD_ARK_WORK_QUEUE_TYPE_CRITICAL ||
                entry.queueType > KSWORD_ARK_WORK_QUEUE_TYPE_SHARED_WORKER ||
                entry.nodeIndex >= nodeCount ||
                (entry.flags & ~KSWORD_ARK_WORK_QUEUE_ENTRY_VALID_MASK) != 0UL ||
                entry.status > KSWORD_ARK_WORK_QUEUE_ENTRY_STATUS_THREAD_IDENTITY_FAILED ||
                entry.reserved0 != 0UL ||
                entry.queueAddress == 0ULL ||
                (entry.flags & KSWORD_ARK_WORK_QUEUE_ENTRY_QUEUE_VALIDATED) == 0UL)
            {
                return false;
            }

            if (entry.rowKind == KSWORD_ARK_WORK_QUEUE_ROW_WORK_ITEM)
            {
                if (entry.queueType == KSWORD_ARK_WORK_QUEUE_TYPE_SHARED_WORKER ||
                    entry.priorityIndex >= KSWORD_ARK_WORK_QUEUE_PRIORITY_COUNT ||
                    entry.workItemAddress == 0ULL ||
                    entry.threadObject != 0ULL ||
                    entry.threadId != 0UL ||
                    entry.threadCreateTime100ns != 0ULL)
                {
                    return false;
                }
            }
            else if (entry.queueType != KSWORD_ARK_WORK_QUEUE_TYPE_SHARED_WORKER ||
                     entry.priorityIndex != std::numeric_limits<unsigned long>::max() ||
                     entry.workItemAddress != 0ULL ||
                     entry.threadObject == 0ULL)
            {
                return false;
            }

            if ((entry.flags & KSWORD_ARK_WORK_QUEUE_ENTRY_PARAMETER_PRESENT) != 0UL &&
                entry.parameterAddress == 0ULL)
            {
                return false;
            }
            if (((entry.flags & KSWORD_ARK_WORK_QUEUE_ENTRY_ROUTINE_PRESENT) != 0UL) !=
                (entry.routineAddress != 0ULL) ||
                ((entry.flags & KSWORD_ARK_WORK_QUEUE_ENTRY_PARAMETER_PRESENT) != 0UL) !=
                (entry.parameterAddress != 0ULL))
            {
                return false;
            }
            if ((entry.flags & KSWORD_ARK_WORK_QUEUE_ENTRY_EXECUTABLE_SECTION) != 0UL &&
                (entry.flags & KSWORD_ARK_WORK_QUEUE_ENTRY_MODULE_RESOLVED) == 0UL)
            {
                return false;
            }
            if (((entry.flags & KSWORD_ARK_WORK_QUEUE_ENTRY_MODULE_RESOLVED) != 0UL) !=
                (entry.moduleBase != 0ULL && entry.moduleSize != 0UL))
            {
                return false;
            }
            const bool kThreadIdentityPresent =
                entry.threadId != 0UL &&
                entry.threadCreateTime100ns != 0ULL;
            if (((entry.flags & KSWORD_ARK_WORK_QUEUE_ENTRY_THREAD_IDENTITY_VALID) != 0UL) !=
                    kThreadIdentityPresent ||
                ((entry.flags & KSWORD_ARK_WORK_QUEUE_ENTRY_THREAD_IDENTITY_VALID) != 0UL &&
                 (entry.flags & KSWORD_ARK_WORK_QUEUE_ENTRY_THREAD_REFERENCED) == 0UL))
            {
                return false;
            }
            if (entry.status == KSWORD_ARK_WORK_QUEUE_ENTRY_STATUS_OK &&
                ((entry.flags &
                  (KSWORD_ARK_WORK_QUEUE_ENTRY_ROUTINE_PRESENT |
                   KSWORD_ARK_WORK_QUEUE_ENTRY_MODULE_RESOLVED |
                   KSWORD_ARK_WORK_QUEUE_ENTRY_EXECUTABLE_SECTION)) !=
                 (KSWORD_ARK_WORK_QUEUE_ENTRY_ROUTINE_PRESENT |
                  KSWORD_ARK_WORK_QUEUE_ENTRY_MODULE_RESOLVED |
                  KSWORD_ARK_WORK_QUEUE_ENTRY_EXECUTABLE_SECTION)))
            {
                return false;
            }
            return true;
        }
    }

    WorkQueueEnumResult DriverClient::enumerateWorkQueues(
        const unsigned long flags,
        const unsigned long maxEntries) const
    {
        WorkQueueEnumResult result{};
        if (flags == 0UL ||
            (flags & ~KSWORD_ARK_WORK_QUEUE_FLAG_VALID_MASK) != 0UL ||
            maxEntries == 0UL ||
            maxEntries > KSWORD_ARK_WORK_QUEUE_MAX_ENTRIES)
        {
            result.io.win32Error = ERROR_INVALID_PARAMETER;
            result.io.message = "invalid work-queue enumeration arguments";
            return result;
        }

        KSWORD_ARK_ENUM_WORK_QUEUE_REQUEST request{};
        request.size = sizeof(request);
        request.version = KSWORD_ARK_WORK_QUEUE_PROTOCOL_VERSION;
        request.flags = flags;
        request.maxEntries = maxEntries;

        const std::size_t kResponseBytes =
            kWorkQueueHeaderSize +
            (static_cast<std::size_t>(maxEntries) *
             sizeof(KSWORD_ARK_WORK_QUEUE_ENTRY));
        std::vector<std::uint8_t> responseBuffer(kResponseBytes, 0U);
        result.io = deviceIoControl(
            IOCTL_KSWORD_ARK_ENUM_WORK_QUEUE,
            &request,
            static_cast<unsigned long>(sizeof(request)),
            responseBuffer.data(),
            static_cast<unsigned long>(responseBuffer.size()));
        if (!result.io.ok)
        {
            result.unsupported = detail::isUnsupportedIoctlError(result.io.win32Error);
            result.io.message = result.unsupported
                ? "IOCTL_KSWORD_ARK_ENUM_WORK_QUEUE unsupported or driver version is too old"
                : "DeviceIoControl(IOCTL_KSWORD_ARK_ENUM_WORK_QUEUE) failed, error=" +
                    std::to_string(result.io.win32Error);
            return result;
        }
        if (result.io.bytesReturned < kWorkQueueHeaderSize ||
            result.io.bytesReturned > responseBuffer.size())
        {
            rejectWorkQueueResponse(
                &result,
                "work-queue response length is outside the fixed protocol boundary");
            return result;
        }

        const auto* const kHeader =
            reinterpret_cast<const KSWORD_ARK_ENUM_WORK_QUEUE_RESPONSE*>(
                responseBuffer.data());
        if (!workQueueHeaderIsConsistent(*kHeader) ||
            kHeader->returnedCount > maxEntries)
        {
            rejectWorkQueueResponse(
                &result,
                "work-queue response header failed size/version/status/reserved/count validation");
            return result;
        }

        const std::size_t kExpectedBytes =
            kWorkQueueHeaderSize +
            (static_cast<std::size_t>(kHeader->returnedCount) *
             sizeof(KSWORD_ARK_WORK_QUEUE_ENTRY));
        if (kExpectedBytes != result.io.bytesReturned)
        {
            rejectWorkQueueResponse(
                &result,
                "work-queue response byte count does not match returnedCount");
            return result;
        }

        result.version = static_cast<std::uint32_t>(kHeader->version);
        result.queryStatus = static_cast<std::uint32_t>(kHeader->queryStatus);
        result.statusFlags = static_cast<std::uint32_t>(kHeader->statusFlags);
        result.totalCount = static_cast<std::uint32_t>(kHeader->totalCount);
        result.returnedCount = static_cast<std::uint32_t>(kHeader->returnedCount);
        result.nodeCount = static_cast<std::uint32_t>(kHeader->nodeCount);
        result.queuesVisited = static_cast<std::uint32_t>(kHeader->queuesVisited);
        result.corruptListCount = static_cast<std::uint32_t>(kHeader->corruptListCount);
        result.readFailureCount = static_cast<std::uint32_t>(kHeader->readFailureCount);
        result.referenceFailureCount = static_cast<std::uint32_t>(kHeader->referenceFailureCount);
        result.lastStatus = static_cast<long>(kHeader->lastStatus);
        result.io.ntStatus = result.lastStatus;
        result.unsupported =
            result.queryStatus == KSWORD_ARK_WORK_QUEUE_QUERY_STATUS_UNSUPPORTED ||
            result.queryStatus == KSWORD_ARK_WORK_QUEUE_QUERY_STATUS_INVALID_LAYOUT ||
            result.queryStatus == KSWORD_ARK_WORK_QUEUE_QUERY_STATUS_IDENTITY_MISMATCH;

        result.entries.reserve(kHeader->returnedCount);
        for (std::size_t index = 0U;
             index < static_cast<std::size_t>(kHeader->returnedCount);
             ++index)
        {
            const std::size_t kEntryOffset =
                kWorkQueueHeaderSize +
                (index * sizeof(KSWORD_ARK_WORK_QUEUE_ENTRY));
            const auto* const kSource =
                reinterpret_cast<const KSWORD_ARK_WORK_QUEUE_ENTRY*>(
                    responseBuffer.data() + kEntryOffset);
            if (!workQueueEntryIsConsistent(*kSource, kHeader->nodeCount))
            {
                rejectWorkQueueResponse(
                    &result,
                    "work-queue entry failed size/kind/flags/reserved/identity validation");
                return result;
            }

            WorkQueueEntry entry{};
            entry.rowKind = static_cast<std::uint32_t>(kSource->rowKind);
            entry.queueType = static_cast<std::uint32_t>(kSource->queueType);
            entry.priorityIndex = static_cast<std::uint32_t>(kSource->priorityIndex);
            entry.nodeIndex = static_cast<std::uint32_t>(kSource->nodeIndex);
            entry.flags = static_cast<std::uint32_t>(kSource->flags);
            entry.status = static_cast<std::uint32_t>(kSource->status);
            entry.queueAddress = static_cast<std::uint64_t>(kSource->queueAddress);
            entry.workItemAddress = static_cast<std::uint64_t>(kSource->workItemAddress);
            entry.routineAddress = static_cast<std::uint64_t>(kSource->routineAddress);
            entry.parameterAddress = static_cast<std::uint64_t>(kSource->parameterAddress);
            entry.threadObject = static_cast<std::uint64_t>(kSource->threadObject);
            entry.threadId = static_cast<std::uint32_t>(kSource->threadId);
            entry.threadCreateTime100ns =
                static_cast<std::uint64_t>(kSource->threadCreateTime100ns);
            entry.moduleBase = static_cast<std::uint64_t>(kSource->moduleBase);
            entry.moduleSize = static_cast<std::uint32_t>(kSource->moduleSize);
            entry.moduleName =
                boundedWorkQueueAnsi(kSource->moduleName, sizeof(kSource->moduleName));
            entry.modulePath =
                boundedWorkQueueAnsi(kSource->modulePath, sizeof(kSource->modulePath));
            result.entries.push_back(std::move(entry));
        }

        std::ostringstream stream;
        stream << "version=" << result.version
            << ", queryStatus=" << result.queryStatus
            << ", flags=0x" << std::hex << std::uppercase << result.statusFlags
            << std::dec << ", total=" << result.totalCount
            << ", returned=" << result.returnedCount
            << ", nodes=" << result.nodeCount
            << ", queues=" << result.queuesVisited
            << ", corrupt=" << result.corruptListCount
            << ", readFailures=" << result.readFailureCount
            << ", referenceFailures=" << result.referenceFailureCount
            << ", lastStatus=0x" << std::hex << std::uppercase
            << static_cast<unsigned long>(result.lastStatus);
        result.io.message = stream.str();
        return result;
    }
}

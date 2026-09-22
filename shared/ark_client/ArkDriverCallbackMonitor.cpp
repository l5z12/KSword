#include "ArkDriverClient.h"
#include "ArkDriverResponseSupport.h"

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <limits>
#include <sstream>
#include <utility>

static_assert(sizeof(KSWORD_ARK_CALLBACK_MONITOR_CONTROL_REQUEST) == 24U);
static_assert(sizeof(KSWORD_ARK_CALLBACK_MONITOR_STATUS_RESPONSE) == 56U);
static_assert(sizeof(KSWORD_ARK_CALLBACK_MONITOR_EVENT) == 1264U);
static_assert(sizeof(KSWORD_ARK_CALLBACK_MONITOR_READ_REQUEST) == 24U);
static_assert(offsetof(KSWORD_ARK_CALLBACK_MONITOR_READ_RESPONSE, records) == 72U);

namespace ksword::ark
{
    namespace
    {


        void parseCallbackMonitorStatus(
            CallbackMonitorStatusResult& result,
            const KSWORD_ARK_CALLBACK_MONITOR_STATUS_RESPONSE& response)
        {
            result.version = static_cast<std::uint32_t>(response.version);
            result.runtimeFlags = static_cast<std::uint32_t>(response.runtimeFlags);
            result.categoryMask = static_cast<std::uint32_t>(response.categoryMask);
            result.registeredCategoryMask = static_cast<std::uint32_t>(response.registeredCategoryMask);
            result.ringCapacity = static_cast<std::uint32_t>(response.ringCapacity);
            result.queuedCount = static_cast<std::uint32_t>(response.queuedCount);
            result.latestSequence = static_cast<std::uint64_t>(response.latestSequence);
            result.droppedCount = static_cast<std::uint64_t>(response.droppedCount);
            result.lastStatus = static_cast<long>(response.lastStatus);
            result.minifilterStartStatus = static_cast<long>(response.minifilterStartStatus);
            result.io.ntStatus = result.lastStatus;
        }

        CallbackMonitorStatusResult controlCallbackMonitorImpl(
            const DriverClient& client,
            DriverHandle* const handle,
            const unsigned long action,
            const unsigned long categoryMask)
        {
            CallbackMonitorStatusResult result{};
            KSWORD_ARK_CALLBACK_MONITOR_CONTROL_REQUEST request{};
            KSWORD_ARK_CALLBACK_MONITOR_STATUS_RESPONSE response{};

            request.version = KSWORD_ARK_CALLBACK_MONITOR_PROTOCOL_VERSION;
            request.size = sizeof(request);
            request.action = action;
            request.categoryMask = categoryMask & KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_ALL;
            result.io = client.deviceIoControl(
                IOCTL_KSWORD_ARK_CALLBACK_MONITOR_CONTROL,
                &request,
                static_cast<unsigned long>(sizeof(request)),
                &response,
                static_cast<unsigned long>(sizeof(response)),
                handle);
            result.unsupported = !result.io.ok &&
                detail::isUnsupportedIoctlError(result.io.win32Error);
            if (result.io.bytesReturned >= sizeof(response))
            {
                parseCallbackMonitorStatus(result, response);
            }
            if (result.io.ok &&
                (result.io.bytesReturned != sizeof(response) ||
                 response.version != KSWORD_ARK_CALLBACK_MONITOR_PROTOCOL_VERSION ||
                 response.size != sizeof(response)))
            {
                result.io.ok = false;
                result.io.win32Error = ERROR_INVALID_DATA;
            }

            std::ostringstream stream;
            stream << "callback-monitor control action=" << action
                << ", ioctl=" << (result.io.ok ? "ok" : "fail")
                << ", win32=" << result.io.win32Error
                << ", mask=0x" << std::hex << result.categoryMask
                << ", registered=0x" << result.registeredCategoryMask
                << ", last=0x" << static_cast<unsigned long>(result.lastStatus)
                << std::dec << ", latest=" << result.latestSequence
                << ", dropped=" << result.droppedCount;
            result.io.message = stream.str();
            return result;
        }

        CallbackMonitorStatusResult queryCallbackMonitorStatusImpl(
            const DriverClient& client,
            DriverHandle* const handle)
        {
            CallbackMonitorStatusResult result{};
            KSWORD_ARK_CALLBACK_MONITOR_STATUS_RESPONSE response{};

            result.io = client.deviceIoControl(
                IOCTL_KSWORD_ARK_CALLBACK_MONITOR_QUERY,
                nullptr,
                0UL,
                &response,
                static_cast<unsigned long>(sizeof(response)),
                handle);
            result.unsupported = !result.io.ok &&
                detail::isUnsupportedIoctlError(result.io.win32Error);
            if (!result.io.ok)
            {
                result.io.message = result.unsupported
                    ? "IOCTL_KSWORD_ARK_CALLBACK_MONITOR_QUERY unsupported by current driver"
                    : "DeviceIoControl(IOCTL_KSWORD_ARK_CALLBACK_MONITOR_QUERY) failed, error=" +
                        std::to_string(result.io.win32Error);
                return result;
            }
            if (result.io.bytesReturned != sizeof(response) ||
                response.version != KSWORD_ARK_CALLBACK_MONITOR_PROTOCOL_VERSION ||
                response.size != sizeof(response))
            {
                result.io.ok = false;
                result.io.win32Error = ERROR_INVALID_DATA;
                result.io.message = "callback-monitor status response is invalid";
                return result;
            }

            parseCallbackMonitorStatus(result, response);
            result.io.message = "callback-monitor status query succeeded";
            return result;
        }

        CallbackMonitorReadResult readCallbackMonitorImpl(
            const DriverClient& client,
            DriverHandle* const handle,
            const std::uint64_t afterSequence,
            const unsigned long maxRecords)
        {
            CallbackMonitorReadResult result{};
            const unsigned long kRequestedRecords = std::min<unsigned long>(
                maxRecords == 0UL ? KSWORD_ARK_CALLBACK_MONITOR_DEFAULT_READ_RECORDS : maxRecords,
                KSWORD_ARK_CALLBACK_MONITOR_MAX_READ_RECORDS);
            constexpr std::size_t kResponseHeaderBytes =
                offsetof(KSWORD_ARK_CALLBACK_MONITOR_READ_RESPONSE, records);
            const std::size_t kOutputBytes = kResponseHeaderBytes +
                (static_cast<std::size_t>(kRequestedRecords) * sizeof(KSWORD_ARK_CALLBACK_MONITOR_EVENT));
            KSWORD_ARK_CALLBACK_MONITOR_READ_REQUEST request{};
            std::vector<unsigned char> outputBuffer(kOutputBytes, 0U);

            request.version = KSWORD_ARK_CALLBACK_MONITOR_PROTOCOL_VERSION;
            request.size = sizeof(request);
            request.maxRecords = kRequestedRecords;
            request.afterSequence = afterSequence;
            result.io = client.deviceIoControl(
                IOCTL_KSWORD_ARK_CALLBACK_MONITOR_READ,
                &request,
                static_cast<unsigned long>(sizeof(request)),
                outputBuffer.data(),
                static_cast<unsigned long>(outputBuffer.size()),
                handle);
            result.unsupported = !result.io.ok &&
                detail::isUnsupportedIoctlError(result.io.win32Error);
            if (!result.io.ok)
            {
                result.io.message = result.unsupported
                    ? "IOCTL_KSWORD_ARK_CALLBACK_MONITOR_READ unsupported by current driver"
                    : "DeviceIoControl(IOCTL_KSWORD_ARK_CALLBACK_MONITOR_READ) failed, error=" +
                        std::to_string(result.io.win32Error);
                return result;
            }
            if (result.io.bytesReturned < kResponseHeaderBytes)
            {
                result.io.ok = false;
                result.io.win32Error = ERROR_INSUFFICIENT_BUFFER;
                result.io.message = "callback-monitor read response header is incomplete";
                return result;
            }

            KSWORD_ARK_CALLBACK_MONITOR_READ_RESPONSE header{};
            std::memcpy(&header, outputBuffer.data(), kResponseHeaderBytes);
            if (header.version != KSWORD_ARK_CALLBACK_MONITOR_PROTOCOL_VERSION ||
                header.entrySize != sizeof(KSWORD_ARK_CALLBACK_MONITOR_EVENT) ||
                header.returnedCount > kRequestedRecords ||
                header.ringCapacity == 0UL)
            {
                result.io.ok = false;
                result.io.win32Error = ERROR_INVALID_DATA;
                result.io.message = "callback-monitor read protocol header is invalid";
                return result;
            }

            const std::size_t kExpectedResponseBytes = kResponseHeaderBytes +
                (static_cast<std::size_t>(header.returnedCount) * header.entrySize);
            if (header.size != kExpectedResponseBytes ||
                kExpectedResponseBytes != result.io.bytesReturned ||
                header.nextSequence > header.latestSequence ||
                (header.latestSequence == 0ULL &&
                 (header.firstAvailableSequence != 0ULL ||
                  header.nextSequence != 0ULL ||
                  header.returnedCount != 0UL)) ||
                (header.latestSequence != 0ULL &&
                 (header.firstAvailableSequence == 0ULL ||
                  header.firstAvailableSequence > header.latestSequence)) ||
                (afterSequence <= header.latestSequence &&
                 header.nextSequence < afterSequence) ||
                (afterSequence > header.latestSequence &&
                 (header.responseFlags & KSWORD_ARK_CALLBACK_MONITOR_READ_FLAG_OVERFLOW) == 0UL))
            {
                result.io.ok = false;
                result.io.win32Error = ERROR_INVALID_DATA;
                result.io.message = "callback-monitor cursor metadata is invalid";
                return result;
            }

            result.runtimeFlags = static_cast<std::uint32_t>(header.runtimeFlags);
            result.categoryMask = static_cast<std::uint32_t>(header.categoryMask);
            result.responseFlags = static_cast<std::uint32_t>(header.responseFlags);
            result.ringCapacity = static_cast<std::uint32_t>(header.ringCapacity);
            result.firstAvailableSequence = static_cast<std::uint64_t>(header.firstAvailableSequence);
            result.latestSequence = static_cast<std::uint64_t>(header.latestSequence);
            result.nextSequence = static_cast<std::uint64_t>(header.nextSequence);
            result.droppedCount = static_cast<std::uint64_t>(header.droppedCount);
            result.lostBeforeFirst = static_cast<std::uint64_t>(header.lostBeforeFirst);
            const unsigned char* const kFirstRecord = outputBuffer.data() + kResponseHeaderBytes;
            std::uint64_t effectiveAfterSequence = afterSequence;
            if (effectiveAfterSequence > result.latestSequence)
            {
                effectiveAfterSequence = 0ULL;
            }
            std::uint64_t expectedFirstSequence = 0ULL;
            if (header.returnedCount != 0UL)
            {
                if (effectiveAfterSequence == std::numeric_limits<std::uint64_t>::max())
                {
                    result.io.ok = false;
                    result.io.win32Error = ERROR_INVALID_DATA;
                    result.io.message = "callback-monitor event record is invalid";
                    return result;
                }
                expectedFirstSequence = std::max(
                    effectiveAfterSequence + 1ULL,
                    result.firstAvailableSequence);
            }
            result.records.reserve(static_cast<std::size_t>(header.returnedCount));
            std::uint64_t previousSequence = 0ULL;
            for (std::size_t recordIndex = 0U;
                 recordIndex < static_cast<std::size_t>(header.returnedCount);
                 ++recordIndex)
            {
                KSWORD_ARK_CALLBACK_MONITOR_EVENT packet{};
                std::memcpy(
                    &packet,
                    kFirstRecord + (recordIndex * header.entrySize),
                    sizeof(packet));
                if (packet.version != KSWORD_ARK_CALLBACK_MONITOR_PROTOCOL_VERSION ||
                    packet.size != sizeof(packet) ||
                    packet.sequence < header.firstAvailableSequence ||
                    packet.sequence > header.latestSequence ||
                    (recordIndex == 0U && packet.sequence != expectedFirstSequence) ||
                    (previousSequence != 0ULL && packet.sequence != previousSequence + 1ULL))
                {
                    result.io.ok = false;
                    result.io.win32Error = ERROR_INVALID_DATA;
                    result.io.message = "callback-monitor event record is invalid";
                    result.records.clear();
                    return result;
                }
                previousSequence = static_cast<std::uint64_t>(packet.sequence);

                CallbackMonitorEventRow record{};
                record.sequence = static_cast<std::uint64_t>(packet.sequence);
                record.timeUtc100ns = static_cast<std::int64_t>(packet.timeUtc100ns);
                record.category = static_cast<std::uint32_t>(packet.category);
                record.operation = static_cast<std::uint32_t>(packet.operation);
                record.flags = static_cast<std::uint32_t>(packet.flags);
                record.resultStatus = static_cast<long>(packet.resultStatus);
                record.originatingProcessId = static_cast<std::uint32_t>(packet.originatingProcessId);
                record.originatingThreadId = static_cast<std::uint32_t>(packet.originatingThreadId);
                record.targetProcessId = static_cast<std::uint32_t>(packet.targetProcessId);
                record.targetThreadId = static_cast<std::uint32_t>(packet.targetThreadId);
                record.parentProcessId = static_cast<std::uint32_t>(packet.parentProcessId);
                record.sessionId = static_cast<std::uint32_t>(packet.sessionId);
                record.originalAccess = static_cast<std::uint32_t>(packet.originalAccess);
                record.desiredAccess = static_cast<std::uint32_t>(packet.desiredAccess);
                record.objectType = static_cast<std::uint32_t>(packet.objectType);
                record.detailCode = static_cast<std::uint32_t>(packet.detailCode);
                record.address = static_cast<std::uint64_t>(packet.address);
                record.regionSize = static_cast<std::uint64_t>(packet.regionSize);
                record.processName = detail::readFixedString(
                    packet.processName,
                    KSWORD_ARK_CALLBACK_MONITOR_PROCESS_NAME_CHARS);
                record.path = detail::readFixedString(
                    packet.path,
                    KSWORD_ARK_CALLBACK_MONITOR_PATH_CHARS);
                result.records.push_back(std::move(record));
            }
            if (previousSequence != 0ULL && previousSequence != result.nextSequence)
            {
                result.io.ok = false;
                result.io.win32Error = ERROR_INVALID_DATA;
                result.io.message = "callback-monitor cursor metadata is invalid";
                result.records.clear();
                return result;
            }

            std::ostringstream stream;
            stream << "callback-monitor read returned=" << header.returnedCount
                << ", next=" << result.nextSequence
                << ", latest=" << result.latestSequence
                << ", lost=" << result.lostBeforeFirst
                << ", dropped=" << result.droppedCount;
            result.io.message = stream.str();
            return result;
        }
    }

    CallbackMonitorStatusResult DriverClient::controlCallbackMonitor(
        const unsigned long action,
        const unsigned long categoryMask) const
    {
        return controlCallbackMonitorImpl(*this, nullptr, action, categoryMask);
    }

    CallbackMonitorStatusResult DriverClient::controlCallbackMonitor(
        DriverHandle& handle,
        const unsigned long action,
        const unsigned long categoryMask) const
    {
        return controlCallbackMonitorImpl(*this, &handle, action, categoryMask);
    }

    CallbackMonitorStatusResult DriverClient::queryCallbackMonitorStatus() const
    {
        return queryCallbackMonitorStatusImpl(*this, nullptr);
    }

    CallbackMonitorStatusResult DriverClient::queryCallbackMonitorStatus(DriverHandle& handle) const
    {
        return queryCallbackMonitorStatusImpl(*this, &handle);
    }

    CallbackMonitorReadResult DriverClient::readCallbackMonitor(
        const std::uint64_t afterSequence,
        const unsigned long maxRecords) const
    {
        return readCallbackMonitorImpl(*this, nullptr, afterSequence, maxRecords);
    }

    CallbackMonitorReadResult DriverClient::readCallbackMonitor(
        DriverHandle& handle,
        const std::uint64_t afterSequence,
        const unsigned long maxRecords) const
    {
        return readCallbackMonitorImpl(*this, &handle, afterSequence, maxRecords);
    }
}

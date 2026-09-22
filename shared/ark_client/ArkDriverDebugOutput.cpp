#include "ArkDriverClient.h"
#include "ArkDriverResponseSupport.h"

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <sstream>
#include <utility>

namespace ksword::ark
{
    namespace
    {

        // Parse fixed control responses; retain driver diagnostic fields even if the control action fails.
        DebugOutputControlResult controlDebugOutputImpl(
            const DriverClient& client,
            DriverHandle* handle,
            const unsigned long action)
        {
            DebugOutputControlResult result{};
            KSWORD_ARK_DEBUG_OUTPUT_CONTROL_REQUEST request{};
            KSWORD_ARK_DEBUG_OUTPUT_CONTROL_RESPONSE response{};

            request.version = KSWORD_ARK_DEBUG_OUTPUT_PROTOCOL_VERSION;
            request.size = sizeof(request);
            request.action = action;
            result.io = client.deviceIoControl(
                IOCTL_KSWORD_ARK_DEBUG_OUTPUT_CONTROL,
                &request,
                static_cast<unsigned long>(sizeof(request)),
                &response,
                static_cast<unsigned long>(sizeof(response)),
                handle);
            result.unsupported = !result.io.ok &&
                detail::isUnsupportedIoctlError(result.io.win32Error);

            // On a fixed-size complete response, copy fields one by one to avoid UI dependency on protocol structure alignment.
            if (result.io.bytesReturned >= sizeof(response))
            {
                result.version = static_cast<std::uint32_t>(response.version);
                result.runtimeFlags = static_cast<std::uint32_t>(response.runtimeFlags);
                result.ringCapacity = static_cast<std::uint32_t>(response.ringCapacity);
                result.queuedCount = static_cast<std::uint32_t>(response.queuedCount);
                result.latestSequence = static_cast<std::uint64_t>(response.latestSequence);
                result.droppedCount = static_cast<std::uint64_t>(response.droppedCount);
                result.registrationStatus = static_cast<long>(response.registrationStatus);
                result.lastStatus = static_cast<long>(response.lastStatus);
                result.io.ntStatus = result.lastStatus;
            }
            if (result.io.ok &&
                (result.io.bytesReturned < sizeof(response) ||
                 response.version != KSWORD_ARK_DEBUG_OUTPUT_PROTOCOL_VERSION ||
                 response.size < sizeof(response)))
            {
                result.io.ok = false;
                result.io.win32Error = ERROR_INVALID_DATA;
            }

            std::ostringstream stream;
            stream << "debug-output control action=" << action
                << ", ioctl=" << (result.io.ok ? "ok" : "fail")
                << ", win32=" << result.io.win32Error
                << ", flags=0x" << std::hex << result.runtimeFlags
                << ", register=0x" << static_cast<unsigned long>(result.registrationStatus)
                << ", last=0x" << static_cast<unsigned long>(result.lastStatus)
                << std::dec << ", queued=" << result.queuedCount
                << ", dropped=" << result.droppedCount;
            result.io.message = stream.str();
            return result;
        }

        // Parse variable-length drain response, strictly bounded by both bytesReturned and entrySize.
        DebugOutputDrainResult drainDebugOutputImpl(
            const DriverClient& client,
            DriverHandle* handle,
            const std::uint64_t afterSequence,
            const unsigned long maxRecords)
        {
            DebugOutputDrainResult result{};
            const unsigned long kRequestedRecords = std::min<unsigned long>(
                maxRecords == 0UL ? KSWORD_ARK_DEBUG_OUTPUT_DEFAULT_DRAIN_RECORDS : maxRecords,
                KSWORD_ARK_DEBUG_OUTPUT_MAX_DRAIN_RECORDS);
            constexpr std::size_t kResponseHeaderBytes =
                offsetof(KSWORD_ARK_DEBUG_OUTPUT_DRAIN_RESPONSE, records);
            const std::size_t kOutputBytes = kResponseHeaderBytes +
                (static_cast<std::size_t>(kRequestedRecords) * sizeof(KSWORD_ARK_DEBUG_OUTPUT_RECORD));
            KSWORD_ARK_DEBUG_OUTPUT_DRAIN_REQUEST request{};
            std::vector<unsigned char> outputBuffer(kOutputBytes, 0U);

            request.version = KSWORD_ARK_DEBUG_OUTPUT_PROTOCOL_VERSION;
            request.size = sizeof(request);
            request.maxRecords = kRequestedRecords;
            request.afterSequence = afterSequence;
            result.io = client.deviceIoControl(
                IOCTL_KSWORD_ARK_DEBUG_OUTPUT_DRAIN,
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
                    ? "IOCTL_KSWORD_ARK_DEBUG_OUTPUT_DRAIN unsupported by current driver"
                    : "DeviceIoControl(IOCTL_KSWORD_ARK_DEBUG_OUTPUT_DRAIN) failed, error=" +
                        std::to_string(result.io.win32Error);
                return result;
            }
            if (result.io.bytesReturned < kResponseHeaderBytes)
            {
                result.io.ok = false;
                result.io.win32Error = ERROR_INSUFFICIENT_BUFFER;
                result.io.message = "debug-output drain response header is incomplete";
                return result;
            }

            KSWORD_ARK_DEBUG_OUTPUT_DRAIN_RESPONSE header{};
            std::memcpy(&header, outputBuffer.data(), kResponseHeaderBytes);
            if (header.version != KSWORD_ARK_DEBUG_OUTPUT_PROTOCOL_VERSION ||
                header.entrySize < sizeof(KSWORD_ARK_DEBUG_OUTPUT_RECORD))
            {
                result.io.ok = false;
                result.io.win32Error = ERROR_INVALID_DATA;
                result.io.message = "debug-output drain protocol version or entry size is invalid";
                return result;
            }

            result.runtimeFlags = static_cast<std::uint32_t>(header.runtimeFlags);
            result.responseFlags = static_cast<std::uint32_t>(header.responseFlags);
            result.ringCapacity = static_cast<std::uint32_t>(header.ringCapacity);
            result.firstAvailableSequence = static_cast<std::uint64_t>(header.firstAvailableSequence);
            result.latestSequence = static_cast<std::uint64_t>(header.latestSequence);
            result.nextSequence = static_cast<std::uint64_t>(header.nextSequence);
            result.droppedCount = static_cast<std::uint64_t>(header.droppedCount);
            result.lostBeforeFirst = static_cast<std::uint64_t>(header.lostBeforeFirst);

            const std::size_t kAvailableBytes = result.io.bytesReturned - kResponseHeaderBytes;
            const std::size_t kAvailableRecords = kAvailableBytes / header.entrySize;
            const std::size_t kRecordsToParse = std::min<std::size_t>(
                static_cast<std::size_t>(header.returnedCount),
                kAvailableRecords);
            const unsigned char* firstRecord = outputBuffer.data() + kResponseHeaderBytes;
            result.records.reserve(kRecordsToParse);
            for (std::size_t recordIndex = 0; recordIndex < kRecordsToParse; ++recordIndex)
            {
                KSWORD_ARK_DEBUG_OUTPUT_RECORD packet{};
                std::memcpy(
                    &packet,
                    firstRecord + (recordIndex * header.entrySize),
                    sizeof(packet));
                DebugOutputRecord record{};
                record.sequence = static_cast<std::uint64_t>(packet.sequence);
                record.interruptTime100ns = static_cast<std::uint64_t>(packet.interruptTime100ns);
                record.componentId = static_cast<std::uint32_t>(packet.componentId);
                record.level = static_cast<std::uint32_t>(packet.level);
                record.flags = static_cast<std::uint32_t>(packet.flags);
                const std::size_t kTextLength = std::min<std::size_t>(
                    static_cast<std::size_t>(packet.textLengthBytes),
                    sizeof(packet.text));
                record.text.assign(packet.text, packet.text + kTextLength);
                result.records.push_back(std::move(record));
            }

            std::ostringstream stream;
            stream << "debug-output drain returned=" << header.returnedCount
                << ", parsed=" << result.records.size()
                << ", next=" << result.nextSequence
                << ", latest=" << result.latestSequence
                << ", lost=" << result.lostBeforeFirst
                << ", dropped=" << result.droppedCount;
            result.io.message = stream.str();
            return result;
        }
    }

    DebugOutputControlResult DriverClient::controlDebugOutput(const unsigned long action) const
    {
        return controlDebugOutputImpl(*this, nullptr, action);
    }

    DebugOutputControlResult DriverClient::controlDebugOutput(
        DriverHandle& handle,
        const unsigned long action) const
    {
        return controlDebugOutputImpl(*this, &handle, action);
    }

    DebugOutputDrainResult DriverClient::drainDebugOutput(
        const std::uint64_t afterSequence,
        const unsigned long maxRecords) const
    {
        return drainDebugOutputImpl(*this, nullptr, afterSequence, maxRecords);
    }

    DebugOutputDrainResult DriverClient::drainDebugOutput(
        DriverHandle& handle,
        const std::uint64_t afterSequence,
        const unsigned long maxRecords) const
    {
        return drainDebugOutputImpl(*this, &handle, afterSequence, maxRecords);
    }
}

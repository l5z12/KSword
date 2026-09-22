#include "ArkDriverClient.h"
#include "ArkDriverResponseSupport.h"

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <limits>
#include <sstream>
#include <string>
#include <vector>

namespace ksword::ark
{
    namespace
    {
        constexpr std::size_t kTrafficResponseBufferBytes = 1024U * 1024U;


        void markTrafficIoctlUnavailable(
            NetworkTrafficPacketResult& result,
            const char* const operationName)
        {
            if (result.io.ok)
            {
                return;
            }

            result.unsupported = detail::isUnsupportedIoctlError(result.io.win32Error);
            std::ostringstream stream;
            stream << "DeviceIoControl(" << operationName << ") failed, error="
                << result.io.win32Error;
            if (result.unsupported)
            {
                stream << ", unsupported=true";
            }
            result.io.message = stream.str();
        }

        void failTrafficProtocol(
            NetworkTrafficPacketResult& result,
            const char* const operationName,
            const std::string& reason)
        {
            result.io.ok = false;
            result.io.win32Error = ERROR_INVALID_DATA;
            result.io.message = std::string(operationName) + " protocol validation failed: " + reason;
            result.entries.clear();
        }
    }

    NetworkTrafficCaptureControlResult DriverClient::controlNetworkTrafficCapture(
        const bool enabled) const
    {
        constexpr const char* kOperationName =
            "IOCTL_KSWORD_ARK_NETWORK_CONTROL_TRAFFIC_CAPTURE";
        NetworkTrafficCaptureControlResult result{};
        KSWORD_ARK_NETWORK_TRAFFIC_CONTROL_REQUEST request{};

        request.version = KSWORD_ARK_NETWORK_TRAFFIC_PROTOCOL_VERSION;
        request.size = sizeof(request);
        request.action = enabled
            ? KSWORD_ARK_NETWORK_TRAFFIC_CONTROL_ENABLE
            : KSWORD_ARK_NETWORK_TRAFFIC_CONTROL_DISABLE;
        request.flags = KSWORD_ARK_NETWORK_TRAFFIC_CONTROL_FLAG_NONE;
        result.io = deviceIoControl(
            IOCTL_KSWORD_ARK_NETWORK_CONTROL_TRAFFIC_CAPTURE,
            &request,
            sizeof(request),
            &result.response,
            sizeof(result.response));
        if (!result.io.ok)
        {
            result.unsupported =
                detail::isUnsupportedIoctlError(result.io.win32Error);
            std::ostringstream stream;
            stream << "DeviceIoControl(" << kOperationName << ") failed, error="
                << result.io.win32Error;
            if (result.unsupported)
            {
                stream << ", unsupported=true";
            }
            result.io.message = stream.str();
            return result;
        }

        const bool kKnownStatus =
            result.response.status == KSWORD_ARK_NETWORK_STATUS_APPLIED ||
            result.response.status == KSWORD_ARK_NETWORK_STATUS_DISABLED ||
            result.response.status == KSWORD_ARK_NETWORK_STATUS_WFP_UNAVAILABLE ||
            result.response.status == KSWORD_ARK_NETWORK_STATUS_OPERATION_FAILED;
        const bool kEnabledMatchesStatus =
            (result.response.status == KSWORD_ARK_NETWORK_STATUS_APPLIED &&
                result.response.enabled == 1UL) ||
            (result.response.status != KSWORD_ARK_NETWORK_STATUS_APPLIED &&
                result.response.enabled == 0UL);
        if (result.io.bytesReturned != sizeof(result.response) ||
            result.response.version != KSWORD_ARK_NETWORK_TRAFFIC_PROTOCOL_VERSION ||
            result.response.size != sizeof(result.response) ||
            !kKnownStatus ||
            !kEnabledMatchesStatus ||
            result.response.reserved0 != 0UL ||
            result.response.reserved1 != 0UL)
        {
            result.io.ok = false;
            result.io.win32Error = ERROR_INVALID_DATA;
            result.io.message = std::string(kOperationName) +
                " protocol validation failed";
            return result;
        }

        result.io.ntStatus = result.response.lastStatus;
        std::ostringstream summary;
        summary << kOperationName
            << " enabled=" << result.response.enabled
            << ", generation=" << result.response.generation
            << ", status=" << result.response.status
            << ", lastStatus=0x" << std::hex
            << static_cast<unsigned long>(result.response.lastStatus);
        result.io.message = summary.str();
        return result;
    }

    NetworkTrafficPacketResult DriverClient::queryNetworkTrafficPackets(
        const std::uint64_t afterSequence,
        const unsigned long maxRows) const
    {
        constexpr const char* kOperationName =
            "IOCTL_KSWORD_ARK_NETWORK_QUERY_TRAFFIC_PACKETS";
        constexpr std::size_t kHeaderSize =
            sizeof(KSWORD_ARK_NETWORK_TRAFFIC_RESPONSE) -
            sizeof(KSWORD_ARK_NETWORK_TRAFFIC_PACKET_ROW);
        constexpr unsigned long kKnownResponseFlags =
            KSWORD_ARK_NETWORK_TRAFFIC_RESPONSE_FLAG_CURSOR_GAP |
            KSWORD_ARK_NETWORK_TRAFFIC_RESPONSE_FLAG_TRUNCATED |
            KSWORD_ARK_NETWORK_TRAFFIC_RESPONSE_FLAG_CURSOR_RESET;
        constexpr unsigned long kKnownPacketFlags =
            KSWORD_ARK_NETWORK_TRAFFIC_PACKET_FLAG_IPV4 |
            KSWORD_ARK_NETWORK_TRAFFIC_PACKET_FLAG_IPV6 |
            KSWORD_ARK_NETWORK_TRAFFIC_PACKET_FLAG_TRUNCATED |
            KSWORD_ARK_NETWORK_TRAFFIC_PACKET_FLAG_FRAGMENTED;

        NetworkTrafficPacketResult result{};
        KSWORD_ARK_NETWORK_TRAFFIC_QUERY_REQUEST request{};
        request.version = KSWORD_ARK_NETWORK_TRAFFIC_PROTOCOL_VERSION;
        request.size = sizeof(request);
        request.flags = KSWORD_ARK_NETWORK_TRAFFIC_QUERY_FLAG_NONE;
        request.maxRows = maxRows;
        request.afterSequence = afterSequence;

        std::vector<std::uint8_t> responseBuffer(kTrafficResponseBufferBytes, 0U);
        result.io = deviceIoControl(
            IOCTL_KSWORD_ARK_NETWORK_QUERY_TRAFFIC_PACKETS,
            &request,
            sizeof(request),
            responseBuffer.data(),
            static_cast<unsigned long>(responseBuffer.size()));
        if (!result.io.ok)
        {
            markTrafficIoctlUnavailable(result, kOperationName);
            return result;
        }

        if (result.io.bytesReturned < kHeaderSize)
        {
            failTrafficProtocol(
                result,
                kOperationName,
                "response header truncated, bytesReturned=" + std::to_string(result.io.bytesReturned));
            return result;
        }

        const auto* response =
            reinterpret_cast<const KSWORD_ARK_NETWORK_TRAFFIC_RESPONSE*>(responseBuffer.data());
        if (response->version != KSWORD_ARK_NETWORK_TRAFFIC_PROTOCOL_VERSION ||
            response->entrySize != sizeof(KSWORD_ARK_NETWORK_TRAFFIC_PACKET_ROW) ||
            response->size < kHeaderSize ||
            response->size != result.io.bytesReturned ||
            (response->flags & ~kKnownResponseFlags) != 0UL ||
            response->reserved != 0UL)
        {
            failTrafficProtocol(
                result,
                kOperationName,
                "response ABI invalid, version=" + std::to_string(response->version) +
                ", entrySize=" + std::to_string(response->entrySize) +
                ", size=" + std::to_string(response->size) +
                ", flags=" + std::to_string(response->flags));
            return result;
        }

        if (response->status != KSWORD_ARK_NETWORK_STATUS_APPLIED &&
            response->status != KSWORD_ARK_NETWORK_STATUS_DISABLED &&
            response->status != KSWORD_ARK_NETWORK_STATUS_WFP_UNAVAILABLE &&
            response->status != KSWORD_ARK_NETWORK_STATUS_OPERATION_FAILED)
        {
            failTrafficProtocol(
                result,
                kOperationName,
                "response status invalid, status=" + std::to_string(response->status));
            return result;
        }

        const unsigned long kEffectiveRequestedRows =
            maxRows == 0UL
            ? KSWORD_ARK_NETWORK_TRAFFIC_DEFAULT_REQUESTED_ROWS
            : std::min<unsigned long>(
                maxRows,
                KSWORD_ARK_NETWORK_TRAFFIC_MAX_REQUESTED_ROWS);
        if (response->capacity == 0UL ||
            response->availablePacketCount > response->capacity ||
            response->returnedPacketCount > response->availablePacketCount ||
            response->returnedPacketCount > kEffectiveRequestedRows ||
            (((response->flags & KSWORD_ARK_NETWORK_TRAFFIC_RESPONSE_FLAG_TRUNCATED) != 0UL) !=
                (response->availablePacketCount > response->returnedPacketCount)) ||
            (((response->flags & KSWORD_ARK_NETWORK_TRAFFIC_RESPONSE_FLAG_CURSOR_GAP) != 0UL) !=
                (response->cursorGapCount != 0ULL)))
        {
            failTrafficProtocol(
                result,
                kOperationName,
                "response counters/flags invalid, capacity=" + std::to_string(response->capacity) +
                ", available=" + std::to_string(response->availablePacketCount) +
                ", returned=" + std::to_string(response->returnedPacketCount));
            return result;
        }

        if (response->returnedPacketCount >
            (std::numeric_limits<std::size_t>::max() - kHeaderSize) /
            static_cast<std::size_t>(response->entrySize))
        {
            failTrafficProtocol(result, kOperationName, "row byte multiplication overflow");
            return result;
        }

        const std::size_t kRequiredBytes =
            kHeaderSize +
            (static_cast<std::size_t>(response->returnedPacketCount) *
                static_cast<std::size_t>(response->entrySize));
        if (kRequiredBytes != static_cast<std::size_t>(response->size) ||
            kRequiredBytes > static_cast<std::size_t>(result.io.bytesReturned))
        {
            failTrafficProtocol(
                result,
                kOperationName,
                "response row bytes invalid, required=" + std::to_string(kRequiredBytes) +
                ", bytesReturned=" + std::to_string(result.io.bytesReturned));
            return result;
        }

        if ((response->oldestSequence == 0ULL) != (response->newestSequence == 0ULL) ||
            (response->oldestSequence != 0ULL &&
                response->oldestSequence > response->newestSequence) ||
            (response->oldestSequence == 0ULL &&
                (response->availablePacketCount != 0UL ||
                    response->returnedPacketCount != 0UL)))
        {
            failTrafficProtocol(
                result,
                kOperationName,
                "sequence window invalid, oldest=" + std::to_string(response->oldestSequence) +
                ", newest=" + std::to_string(response->newestSequence));
            return result;
        }

        const bool kCursorReset =
            (response->flags & KSWORD_ARK_NETWORK_TRAFFIC_RESPONSE_FLAG_CURSOR_RESET) != 0UL;
        if (kCursorReset &&
            (response->newestSequence == 0ULL || afterSequence <= response->newestSequence))
        {
            failTrafficProtocol(
                result,
                kOperationName,
                "cursor reset inconsistent with afterSequence=" + std::to_string(afterSequence));
            return result;
        }

        std::uint64_t previousSequence = kCursorReset ? 0ULL : afterSequence;
        result.entries.reserve(response->returnedPacketCount);
        for (std::uint32_t index = 0U; index < response->returnedPacketCount; ++index)
        {
            const std::size_t kOffset =
                kHeaderSize +
                (static_cast<std::size_t>(index) *
                    static_cast<std::size_t>(response->entrySize));
            KSWORD_ARK_NETWORK_TRAFFIC_PACKET_ROW row{};
            std::memcpy(&row, responseBuffer.data() + kOffset, sizeof(row));

            const bool kHasIpv4Flag =
                (row.flags & KSWORD_ARK_NETWORK_TRAFFIC_PACKET_FLAG_IPV4) != 0UL;
            const bool kHasIpv6Flag =
                (row.flags & KSWORD_ARK_NETWORK_TRAFFIC_PACKET_FLAG_IPV6) != 0UL;
            const bool kTruncated =
                (row.flags & KSWORD_ARK_NETWORK_TRAFFIC_PACKET_FLAG_TRUNCATED) != 0UL;
            const bool kAddressFamilyMatches =
                (row.addressFamily == KSWORD_ARK_NETWORK_ADDRESS_FAMILY_IPV4 && kHasIpv4Flag && !kHasIpv6Flag) ||
                (row.addressFamily == KSWORD_ARK_NETWORK_ADDRESS_FAMILY_IPV6 && kHasIpv6Flag && !kHasIpv4Flag);
            const bool kPayloadRangeValid =
                row.payloadOffset <= row.totalPacketLength &&
                row.payloadLength <= row.totalPacketLength - row.payloadOffset;
            const bool kCaptureRangeValid =
                row.capturedLength <= KSWORD_ARK_NETWORK_TRAFFIC_MAX_CAPTURE_BYTES &&
                row.capturedLength <= row.totalPacketLength &&
                (kTruncated == (row.capturedLength < row.totalPacketLength));

            if (row.version != KSWORD_ARK_NETWORK_TRAFFIC_PROTOCOL_VERSION ||
                row.size != sizeof(row) ||
                row.sequence <= previousSequence ||
                row.direction != KSWORD_ARK_NETWORK_DIRECTION_INBOUND &&
                    row.direction != KSWORD_ARK_NETWORK_DIRECTION_OUTBOUND ||
                row.protocol != KSWORD_ARK_NETWORK_PROTOCOL_TCP &&
                    row.protocol != KSWORD_ARK_NETWORK_PROTOCOL_UDP ||
                (row.flags & ~kKnownPacketFlags) != 0UL ||
                !kAddressFamilyMatches ||
                !kPayloadRangeValid ||
                !kCaptureRangeValid ||
                row.reserved0 != 0UL ||
                row.reserved1 != 0UL ||
                response->oldestSequence != 0ULL &&
                    (row.sequence < response->oldestSequence ||
                        row.sequence > response->newestSequence))
            {
                failTrafficProtocol(
                    result,
                    kOperationName,
                    "row[" + std::to_string(index) +
                    "] invalid, sequence=" + std::to_string(row.sequence) +
                    ", family=" + std::to_string(row.addressFamily) +
                    ", flags=" + std::to_string(row.flags));
                return result;
            }

            previousSequence = row.sequence;
            result.entries.push_back(row);
        }

        const std::uint64_t kExpectedNextSequence =
            result.entries.empty()
            ? (kCursorReset ? 0ULL : afterSequence)
            : result.entries.back().sequence;
        if (response->nextSequence != kExpectedNextSequence)
        {
            failTrafficProtocol(
                result,
                kOperationName,
                "nextSequence=" + std::to_string(response->nextSequence) +
                ", expected=" + std::to_string(kExpectedNextSequence));
            return result;
        }

        result.version = response->version;
        result.status = response->status;
        result.flags = response->flags;
        result.totalCount = response->availablePacketCount;
        result.returnedCount = response->returnedPacketCount;
        result.entrySize = response->entrySize;
        result.capacity = response->capacity;
        result.oldestSequence = response->oldestSequence;
        result.newestSequence = response->newestSequence;
        result.nextSequence = response->nextSequence;
        result.droppedPacketCount = response->droppedPacketCount;
        result.cursorGapCount = response->cursorGapCount;
        result.lastStatus = response->lastStatus;
        result.io.ntStatus = response->lastStatus;

        std::ostringstream summary;
        summary << kOperationName
            << " rows=" << result.entries.size()
            << "/" << result.returnedCount
            << ", available=" << result.totalCount
            << ", oldest=" << result.oldestSequence
            << ", newest=" << result.newestSequence
            << ", next=" << result.nextSequence
            << ", dropped=" << result.droppedPacketCount
            << ", cursorGap=" << result.cursorGapCount;
        result.io.message = summary.str();
        return result;
    }
}

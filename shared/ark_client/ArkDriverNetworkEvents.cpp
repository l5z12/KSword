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
        // queryNetworkWfpEventAudit:
        // - Input: stable afterSequence cursor and single-row budget
        // - Processing: Send real WFP ALE event IOCTL to verify response size, multiply-add boundary, row ABI, and sequence monotonicity;
        // - Return: NetworkWfpEventResult containing only authorization metadata for flows without payload.
        NetworkWfpEventResult queryNetworkWfpEventAudit(
            const DriverClient& client,
            const std::uint64_t afterSequence,
            const unsigned long maxRows)
        {
            constexpr const char* kOperationName = "IOCTL_KSWORD_ARK_NETWORK_QUERY_WFP_EVENTS";
            constexpr std::size_t kHeaderSize =
                sizeof(KSWORD_ARK_NETWORK_WFP_EVENT_RESPONSE) -
                sizeof(KSWORD_ARK_NETWORK_WFP_EVENT_ROW);
            NetworkWfpEventResult result{};
            KSWORD_ARK_NETWORK_WFP_EVENT_QUERY_REQUEST request{};
            request.version = KSWORD_ARK_NETWORK_WFP_EVENT_PROTOCOL_VERSION;
            request.size = sizeof(request);
            request.flags = KSWORD_ARK_NETWORK_WFP_EVENT_QUERY_FLAG_NONE;
            request.maxRows = maxRows;
            request.afterSequence = afterSequence;

            std::vector<std::uint8_t> responseBuffer(kDefaultAuditBufferBytes, 0U);
            result.io = client.deviceIoControl(
                IOCTL_KSWORD_ARK_NETWORK_QUERY_WFP_EVENTS,
                &request,
                sizeof(request),
                responseBuffer.data(),
                static_cast<unsigned long>(responseBuffer.size()));
            if (!result.io.ok)
            {
                markUnsupportedIfNeeded(result, kOperationName);
                return result;
            }

            const auto kFailProtocol = [&result, kOperationName](const std::string& reason)
            {
                result.io.ok = false;
                result.io.win32Error = ERROR_INVALID_DATA;
                result.io.message = std::string(kOperationName) + " protocol validation failed: " + reason;
            };

            if (result.io.bytesReturned < kHeaderSize)
            {
                kFailProtocol("response header truncated, bytesReturned=" + std::to_string(result.io.bytesReturned));
                return result;
            }

            const auto* response =
                reinterpret_cast<const KSWORD_ARK_NETWORK_WFP_EVENT_RESPONSE*>(responseBuffer.data());
            if (response->version != KSWORD_ARK_NETWORK_WFP_EVENT_PROTOCOL_VERSION)
            {
                kFailProtocol("response version=" + std::to_string(response->version));
                return result;
            }
            if (response->entrySize != sizeof(KSWORD_ARK_NETWORK_WFP_EVENT_ROW))
            {
                kFailProtocol("entrySize=" + std::to_string(response->entrySize));
                return result;
            }
            if (response->size < kHeaderSize ||
                response->size != result.io.bytesReturned)
            {
                kFailProtocol(
                    "response size=" + std::to_string(response->size) +
                    ", bytesReturned=" + std::to_string(result.io.bytesReturned));
                return result;
            }
            constexpr unsigned long kKnownResponseFlags =
                KSWORD_ARK_NETWORK_WFP_EVENT_RESPONSE_FLAG_CURSOR_GAP |
                KSWORD_ARK_NETWORK_WFP_EVENT_RESPONSE_FLAG_TRUNCATED |
                KSWORD_ARK_NETWORK_WFP_EVENT_RESPONSE_FLAG_CURSOR_RESET;
            if ((response->flags & ~kKnownResponseFlags) != 0UL ||
                response->reserved != 0UL ||
                (response->status != KSWORD_ARK_NETWORK_STATUS_APPLIED &&
                    response->status != KSWORD_ARK_NETWORK_STATUS_WFP_UNAVAILABLE &&
                    response->status != KSWORD_ARK_NETWORK_STATUS_OPERATION_FAILED))
            {
                kFailProtocol(
                    "response status/flags/reserved invalid, status=" +
                    std::to_string(response->status) +
                    ", flags=" + std::to_string(response->flags));
                return result;
            }
            if (response->returnedEventCount > response->availableEventCount)
            {
                kFailProtocol(
                    "returnedEventCount=" + std::to_string(response->returnedEventCount) +
                    " exceeds availableEventCount=" + std::to_string(response->availableEventCount));
                return result;
            }

            const unsigned long kEffectiveRequestedRows =
                maxRows == 0UL ?
                KSWORD_ARK_NETWORK_WFP_EVENT_DEFAULT_REQUESTED_ROWS :
                std::min<unsigned long>(maxRows, KSWORD_ARK_NETWORK_WFP_EVENT_MAX_REQUESTED_ROWS);
            if (response->returnedEventCount > kEffectiveRequestedRows)
            {
                kFailProtocol(
                    "returnedEventCount=" + std::to_string(response->returnedEventCount) +
                    " exceeds requested rows=" + std::to_string(kEffectiveRequestedRows));
                return result;
            }
            if (response->returnedEventCount >
                (std::numeric_limits<std::size_t>::max() - kHeaderSize) /
                static_cast<std::size_t>(response->entrySize))
            {
                kFailProtocol("row byte multiplication overflow");
                return result;
            }

            const std::size_t kRequiredBytes =
                kHeaderSize +
                (static_cast<std::size_t>(response->returnedEventCount) *
                    static_cast<std::size_t>(response->entrySize));
            if (kRequiredBytes > static_cast<std::size_t>(result.io.bytesReturned) ||
                kRequiredBytes != static_cast<std::size_t>(response->size))
            {
                kFailProtocol(
                    "row bytes=" + std::to_string(kRequiredBytes) +
                    ", response size=" + std::to_string(response->size) +
                    ", bytesReturned=" + std::to_string(result.io.bytesReturned));
                return result;
            }
            if (response->availableEventCount > response->capacity)
            {
                kFailProtocol(
                    "availableEventCount=" + std::to_string(response->availableEventCount) +
                    " exceeds capacity=" + std::to_string(response->capacity));
                return result;
            }
            if (response->capacity == 0UL ||
                (((response->flags &
                    KSWORD_ARK_NETWORK_WFP_EVENT_RESPONSE_FLAG_TRUNCATED) != 0UL) !=
                    (response->availableEventCount > response->returnedEventCount)) ||
                (((response->flags &
                    KSWORD_ARK_NETWORK_WFP_EVENT_RESPONSE_FLAG_CURSOR_GAP) != 0UL) !=
                    (response->cursorGapCount != 0ULL)))
            {
                kFailProtocol(
                    "capacity/flag counters inconsistent, capacity=" +
                    std::to_string(response->capacity) +
                    ", available=" + std::to_string(response->availableEventCount) +
                    ", returned=" + std::to_string(response->returnedEventCount) +
                    ", cursorGap=" + std::to_string(response->cursorGapCount));
                return result;
            }
            if ((response->oldestSequence == 0ULL) != (response->newestSequence == 0ULL) ||
                (response->oldestSequence != 0ULL &&
                    response->oldestSequence > response->newestSequence) ||
                (response->oldestSequence == 0ULL &&
                    (response->availableEventCount != 0UL ||
                        response->returnedEventCount != 0UL)))
            {
                kFailProtocol(
                    "invalid sequence window oldest=" + std::to_string(response->oldestSequence) +
                    ", newest=" + std::to_string(response->newestSequence));
                return result;
            }

            const bool kCursorReset =
                (response->flags & KSWORD_ARK_NETWORK_WFP_EVENT_RESPONSE_FLAG_CURSOR_RESET) != 0UL;
            if (kCursorReset &&
                (response->newestSequence == 0ULL ||
                    afterSequence <= response->newestSequence))
            {
                kFailProtocol(
                    "cursor reset is inconsistent with afterSequence=" +
                    std::to_string(afterSequence) +
                    ", newest=" + std::to_string(response->newestSequence));
                return result;
            }
            std::uint64_t previousSequence = kCursorReset ? 0ULL : afterSequence;
            constexpr unsigned long kKnownRowFlags =
                KSWORD_ARK_NETWORK_WFP_EVENT_FLAG_NO_PAYLOAD |
                KSWORD_ARK_NETWORK_WFP_EVENT_FLAG_BLOCKED |
                KSWORD_ARK_NETWORK_WFP_EVENT_FLAG_ACTION_WRITE_UNAVAILABLE |
                KSWORD_ARK_NETWORK_WFP_EVENT_FLAG_ALE_CONNECT |
                KSWORD_ARK_NETWORK_WFP_EVENT_FLAG_ALE_RECV_ACCEPT |
                KSWORD_ARK_NETWORK_WFP_EVENT_FLAG_IPV4;
            result.entries.reserve(response->returnedEventCount);
            for (std::uint32_t index = 0U; index < response->returnedEventCount; ++index)
            {
                const std::size_t kOffset =
                    kHeaderSize +
                    (static_cast<std::size_t>(index) *
                        static_cast<std::size_t>(response->entrySize));
                KSWORD_ARK_NETWORK_WFP_EVENT_ROW row{};
                std::memcpy(&row, responseBuffer.data() + kOffset, sizeof(row));
                if (row.version != KSWORD_ARK_NETWORK_WFP_EVENT_PROTOCOL_VERSION ||
                    row.size < sizeof(row) ||
                    row.size > response->entrySize)
                {
                    kFailProtocol(
                        "row[" + std::to_string(index) + "] ABI invalid, version=" +
                        std::to_string(row.version) + ", size=" + std::to_string(row.size));
                    result.entries.clear();
                    return result;
                }
                if (row.sequence <= previousSequence)
                {
                    kFailProtocol(
                        "row[" + std::to_string(index) + "] sequence=" +
                        std::to_string(row.sequence) + " is not strictly increasing after " +
                        std::to_string(previousSequence));
                    result.entries.clear();
                    return result;
                }
                if (row.direction != KSWORD_ARK_NETWORK_DIRECTION_INBOUND &&
                    row.direction != KSWORD_ARK_NETWORK_DIRECTION_OUTBOUND)
                {
                    kFailProtocol(
                        "row[" + std::to_string(index) + "] direction=" +
                        std::to_string(row.direction));
                    result.entries.clear();
                    return result;
                }
                if (row.protocol > std::numeric_limits<std::uint8_t>::max() ||
                    (row.flags & ~kKnownRowFlags) != 0UL ||
                    (row.flags & KSWORD_ARK_NETWORK_WFP_EVENT_FLAG_NO_PAYLOAD) == 0UL ||
                    (row.flags & KSWORD_ARK_NETWORK_WFP_EVENT_FLAG_IPV4) == 0UL ||
                    (((row.flags & KSWORD_ARK_NETWORK_WFP_EVENT_FLAG_ALE_CONNECT) != 0UL) ==
                        ((row.flags & KSWORD_ARK_NETWORK_WFP_EVENT_FLAG_ALE_RECV_ACCEPT) != 0UL)) ||
                    (((row.flags & KSWORD_ARK_NETWORK_WFP_EVENT_FLAG_BLOCKED) != 0UL) &&
                        ((row.flags &
                            KSWORD_ARK_NETWORK_WFP_EVENT_FLAG_ACTION_WRITE_UNAVAILABLE) != 0UL)) ||
                    row.reserved0 != 0UL ||
                    row.reserved1 != 0UL ||
                    (response->oldestSequence != 0ULL &&
                        (row.sequence < response->oldestSequence ||
                            row.sequence > response->newestSequence)))
                {
                    kFailProtocol(
                        "row[" + std::to_string(index) +
                        "] protocol/flags invalid, protocol=" + std::to_string(row.protocol) +
                        ", flags=" + std::to_string(row.flags));
                    result.entries.clear();
                    return result;
                }
                previousSequence = row.sequence;
                result.entries.push_back(row);
            }

            const std::uint64_t kExpectedNextSequence =
                result.entries.empty() ?
                (kCursorReset ? 0ULL : afterSequence) :
                result.entries.back().sequence;
            if (response->nextSequence != kExpectedNextSequence)
            {
                kFailProtocol(
                    "nextSequence=" + std::to_string(response->nextSequence) +
                    ", expected=" + std::to_string(kExpectedNextSequence));
                result.entries.clear();
                return result;
            }

            result.version = response->version;
            result.status = response->status;
            result.flags = response->flags;
            result.totalCount = response->availableEventCount;
            result.returnedCount = response->returnedEventCount;
            result.entrySize = response->entrySize;
            result.capacity = response->capacity;
            result.oldestSequence = response->oldestSequence;
            result.newestSequence = response->newestSequence;
            result.nextSequence = response->nextSequence;
            result.droppedEventCount = response->droppedEventCount;
            result.cursorGapCount = response->cursorGapCount;
            result.lastStatus = response->lastStatus;
            result.io.ntStatus = response->lastStatus;

            std::ostringstream summary;
            summary << appendAuditSummary(
                kOperationName,
                result.totalCount,
                result.returnedCount,
                result.entries.size(),
                result.io.bytesReturned)
                << ", oldest=" << result.oldestSequence
                << ", newest=" << result.newestSequence
                << ", next=" << result.nextSequence
                << ", dropped=" << result.droppedEventCount
                << ", cursorGap=" << result.cursorGapCount;
            result.io.message = summary.str();
            return result;
        }
    }

    NetworkWfpEventResult DriverClient::queryNetworkWfpEvents(
        const std::uint64_t afterSequence,
        const unsigned long maxRows) const
    {
        return queryNetworkWfpEventAudit(*this, afterSequence, maxRows);
    }
}

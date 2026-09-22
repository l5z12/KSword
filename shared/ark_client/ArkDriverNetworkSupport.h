#pragma once

#include "ArkDriverAuditSupport.h"

namespace ksword::ark::detail::network
{
    inline constexpr std::uint32_t kStatusBufferOverflow = 0x80000005UL;
    inline constexpr std::uint32_t kStatusPartialCopy = 0x8000000DUL;

    // validateNetworkAuditHeader:
    // - Input: R0 network audit response header, fixed header size, and operation name;
    // - Processing: Validate protocol version, header size, status, source bit, count, and budget relationship.
    // - Returns: true if variable-length lines can be safely parsed subsequently; on failure, writes synchronously to IoResult.
    template <typename TResponse>
    bool validateNetworkAuditHeader(
        IoResult& io,
        const TResponse& response,
        const std::size_t headerSize,
        const char* const operationName)
    {
        constexpr std::uint32_t kKnownSourceFlags =
            KSWORD_ARK_NETWORK_AUDIT_SOURCE_TCPIP_PDB |
            KSWORD_ARK_NETWORK_AUDIT_SOURCE_NETIO_PDB |
            KSWORD_ARK_NETWORK_AUDIT_SOURCE_NDIS_PDB |
            KSWORD_ARK_NETWORK_AUDIT_SOURCE_RUNTIME_STATE;

        auto fail = [&io, operationName](const std::string& reason)
        {
            io.ok = false;
            io.win32Error = ERROR_INVALID_DATA;
            io.message = std::string(operationName) + " invalid response: " + reason;
            return false;
        };

        if (response.version != KSWORD_ARK_NETWORK_PROTOCOL_VERSION)
        {
            return fail("version=" + std::to_string(response.version));
        }
        if (response.size != headerSize || response.size > io.bytesReturned)
        {
            return fail("size=" + std::to_string(response.size) +
                ", bytesReturned=" + std::to_string(io.bytesReturned));
        }
        if (response.status > KSWORD_ARK_NETWORK_STATUS_AUDIT_STUB)
        {
            return fail("status=" + std::to_string(response.status));
        }
        if ((response.flags & ~KSWORD_ARK_NETWORK_AUDIT_QUERY_FLAG_INCLUDE_ALL) != 0UL)
        {
            return fail("flags=" + std::to_string(response.flags));
        }
        if ((response.sourceFlags & ~kKnownSourceFlags) != 0UL)
        {
            return fail("sourceFlags=" + std::to_string(response.sourceFlags));
        }
        if (response.returnedRowCount > response.totalRowCount)
        {
            return fail("returnedRowCount exceeds totalRowCount");
        }
        if (response.budgetRows != 0UL && response.returnedRowCount > response.budgetRows)
        {
            return fail("returnedRowCount exceeds budgetRows");
        }
        return true;
    }

    // isRetainableNetworkInventoryPartial:
    // - Input: WFP/NDIS response protocol status, NTSTATUS, and actual returned row count;
    // - Processing: Only accept PARTIAL_COPY/BUFFER_OVERFLOW partial snapshots as defined by the driver protocol;
    // - Returns: true indicates the row is valid and can be retained for UI/CLI; other OPERATION_FAILED rows are unavailable.
    inline bool isRetainableNetworkInventoryPartial(
        const std::uint32_t status,
        const long lastStatus,
        const std::uint32_t returnedCount) noexcept
    {
        const std::uint32_t kNormalizedStatus =
            static_cast<std::uint32_t>(lastStatus);
        return status == KSWORD_ARK_NETWORK_STATUS_OPERATION_FAILED &&
            returnedCount != 0U &&
            (kNormalizedStatus == kStatusPartialCopy ||
             kNormalizedStatus == kStatusBufferOverflow);
    }

    // finalizeNetworkInventoryCompleteness:
    // - Input: WFP/NDIS wrapper results with completed protocol boundaries and line-by-line validation;
    // - Processing: Mark as complete/partial/truncated and discard failed rows that do not conform to the partial contract.
    // - Returns: No return value; result updated in place.
    template <typename TResult>
    void finalizeNetworkInventoryCompleteness(TResult& result)
    {
        const bool kApplied =
            result.status == KSWORD_ARK_NETWORK_STATUS_APPLIED;
        const bool kComplete =
            kApplied && result.totalCount == result.returnedCount;
        const bool kCollectorPartial = isRetainableNetworkInventoryPartial(
            result.status,
            result.lastStatus,
            result.returnedCount);
        const bool kAppliedTruncated =
            kApplied && !kComplete;
        result.partial = kCollectorPartial || kAppliedTruncated;
        result.truncated =
            kAppliedTruncated ||
            (kCollectorPartial &&
             (result.totalCount > result.returnedCount ||
              static_cast<std::uint32_t>(result.lastStatus) ==
                  kStatusBufferOverflow));

        if (!kApplied && !kCollectorPartial)
        {
            result.entries.clear();
        }
    }

    // finalizeNetworkEndpointCompleteness:
    // - Input: TCP/UDP results validated against endpoint rows via shared header;
    // - Handling: Endpoint accepts only APPLIED; discard all rows in failure responses.
    // - Returns: None. Simultaneously populates truncated data for explicit UI display.
    inline void finalizeNetworkEndpointCompleteness(
        NetworkEndpointAuditResult& result)
    {
        const bool kApplied =
            result.status == KSWORD_ARK_NETWORK_STATUS_APPLIED;
        const bool kComplete =
            kApplied && result.totalCount == result.returnedCount;
        result.partial = kApplied && !kComplete;
        result.truncated = result.partial;
        if (!kApplied)
        {
            result.entries.clear();
        }
    }

    // appendNetworkAuditState:
    // - Input: generated parse summary and network response status field;
    // - Processing: Append protocol status, NTSTATUS, source, and generation to the diagnostic text.
    // - Returns: A complete structured description ready for UI or logging.
    inline std::string appendNetworkAuditState(
        std::string summary,
        const std::uint32_t status,
        const long lastStatus,
        const std::uint32_t sourceFlags,
        const std::uint32_t generation)
    {
        std::ostringstream stream;
        stream << summary
            << ", protocolStatus=" << status
            << ", lastStatus=0x" << std::hex << static_cast<std::uint32_t>(lastStatus)
            << ", sourceFlags=0x" << sourceFlags
            << std::dec << ", generation=" << generation;
        return stream.str();
    }

    // buildNetworkRequest:
    // - Input: Network audit flags and row budget.
    // - Processing: Fill shared protocol version, structure size, and conservative budget;
    // - Returns: KSWORD_ARK_NETWORK_AUDIT_QUERY_REQUEST.
    inline KSWORD_ARK_NETWORK_AUDIT_QUERY_REQUEST buildNetworkRequest(const unsigned long flags, const unsigned long maxRows)
    {
        KSWORD_ARK_NETWORK_AUDIT_QUERY_REQUEST request{};
        request.version = KSWORD_ARK_NETWORK_PROTOCOL_VERSION;
        request.size = sizeof(request);
        request.flags = flags;
        request.maxRows = maxRows;
        return request;
    }

}

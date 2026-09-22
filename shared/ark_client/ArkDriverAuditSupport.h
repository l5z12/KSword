#pragma once

#include "ArkDriverClient.h"
#include "ArkDriverResponseSupport.h"

#include <algorithm>
#include <cstring>
#include <sstream>
#include <type_traits>

namespace ksword::ark::detail::audit
{
    inline constexpr std::size_t kDefaultAuditBufferBytes = 4U * 1024U * 1024U;

    // validateAuditRows:
    // - Input: Returned byte count, header size, entrySize, minimum row-structure size, and returnedCount;
    // - Processing: Validate variable-length response boundaries and calculate the number of rows that can be safely parsed;
    // - Returns: The number of parseable rows; sets io and returns 0 on failure.
    std::size_t validateAuditRows(
        IoResult& io,
        const std::size_t headerSize,
        const std::uint32_t entrySize,
        const std::size_t minimumEntrySize,
        const std::uint32_t returnedCount,
        const char* const operationName);

    // appendAuditSummary:
    // - Input: operation name, total count, returned count, parsed count, and byte count;
    // - Processing: generate a unified success diagnostic string.
    // - Returns: std::string, which can be written directly to IoResult::message.
    std::string appendAuditSummary(
        const char* const operationName,
        const std::uint32_t totalCount,
        const std::uint32_t returnedCount,
        const std::size_t parsedCount,
        const unsigned long bytesReturned);

    // copyAuditWideToFixed:
    // - Input: Target fixed-width wide character array, capacity, and R3 string;
    // - Processing: zero-initialize, truncate copy, and ensure NUL termination;
    // - Returns: Nothing.
    void copyAuditWideToFixed(wchar_t* const destination, const std::size_t destinationChars, const std::wstring& source);

    // queryNoInputFixedAudit:
    // - Input: DriverClient, IOCTL, fixed response, and operation name;
    // - Processing: Fixed-response IOCTL call without input buffering.
    // - Returns: IoResult, reused for input-less queries by Hyper-V/AppControl, etc.
    template <typename TResponse>
    IoResult queryNoInputFixedAudit(
        const DriverClient& client,
        const unsigned long ioctlCode,
        TResponse& responseOut,
        const char* const operationName)
    {
        IoResult io = client.deviceIoControl(
            ioctlCode,
            nullptr,
            0UL,
            &responseOut,
            static_cast<unsigned long>(sizeof(TResponse)));
        if (!io.ok)
        {
            io.message = std::string("DeviceIoControl(") + operationName + ") failed, error=" + std::to_string(io.win32Error);
            return io;
        }
        if (io.bytesReturned < sizeof(TResponse))
        {
            io.ok = false;
            io.win32Error = ERROR_INSUFFICIENT_BUFFER;
            io.message = std::string(operationName) + " response too small, bytesReturned=" + std::to_string(io.bytesReturned);
        }
        return io;
    }

    // parseVariableRows:
    // - Input: response buffer, header size, row size, and number of rows to parse;
    // - Processing: Use memcpy row-by-row into std::vector to avoid storing dangling pointers directly.
    // - Return: vector of rows; row type must be a trivially copyable protocol structure.
    template <typename TEntry>
    std::vector<TEntry> parseVariableRows(
        const std::vector<std::uint8_t>& responseBuffer,
        const std::size_t headerSize,
        const std::uint32_t entrySize,
        const std::size_t parsedCount)
    {
        static_assert(std::is_trivially_copyable_v<TEntry>, "audit protocol rows must be trivially copyable");
        std::vector<TEntry> rows;
        if (headerSize > responseBuffer.size() || entrySize < sizeof(TEntry))
        {
            return rows;
        }

        // Bound allocation and arithmetic by the actual buffer, even if a caller
        // passes an untrusted row count. A row includes its full protocol stride.
        const std::size_t kAvailableRows = (responseBuffer.size() - headerSize) / entrySize;
        const std::size_t kCount = std::min(parsedCount, kAvailableRows);
        rows.reserve(kCount);
        for (std::size_t index = 0U; index < kCount; ++index)
        {
            const std::size_t kOffset = headerSize + (index * static_cast<std::size_t>(entrySize));

            TEntry row{};
            std::memcpy(&row, responseBuffer.data() + kOffset, sizeof(TEntry));
            rows.push_back(row);
        }
        return rows;
    }

    // markUnsupportedIfNeeded:
    // - Input: any result containing io/unsupported fields and the operation name;
    // - Processing: Populate the unified message and unsupported flag when an IOCTL fails.
    // - Return: No return value; Result is updated in place.
    template <typename TResult>
    void markUnsupportedIfNeeded(TResult& result, const char* const operationName)
    {
        if (result.io.ok)
        {
            return;
        }

        result.unsupported = detail::isUnsupportedIoctlError(result.io.win32Error);
        std::ostringstream stream;
        stream << "DeviceIoControl(" << (operationName != nullptr ? operationName : "audit")
            << ") failed, error=" << result.io.win32Error;
        if (result.unsupported)
        {
            stream << ", unsupported=true";
        }
        result.io.message = stream.str();
    }

    // queryFixedAudit:
    // - Input: DriverClient, IOCTL, optional input, fixed response, and operation name;
    // - Processing: Invoke unified deviceIoControl and verify the fixed response byte count.
    // - Return: IoResult; the fixed response is carried by the responseOut passed by the caller.
    template <typename TRequest, typename TResponse>
    IoResult queryFixedAudit(
        const DriverClient& client,
        const unsigned long ioctlCode,
        TRequest* const request,
        TResponse& responseOut,
        const char* const operationName)
    {
        IoResult io = client.deviceIoControl(
            ioctlCode,
            request,
            request != nullptr ? static_cast<unsigned long>(sizeof(TRequest)) : 0UL,
            &responseOut,
            static_cast<unsigned long>(sizeof(TResponse)));
        if (!io.ok)
        {
            io.message = std::string("DeviceIoControl(") + operationName + ") failed, error=" + std::to_string(io.win32Error);
            return io;
        }
        if (io.bytesReturned < sizeof(TResponse))
        {
            io.ok = false;
            io.win32Error = ERROR_INSUFFICIENT_BUFFER;
            io.message = std::string(operationName) + " response too small, bytesReturned=" + std::to_string(io.bytesReturned);
        }
        return io;
    }
}

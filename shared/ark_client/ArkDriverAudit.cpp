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

namespace ksword::ark::detail::audit
{
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
        const char* const operationName)
    {
        if (io.bytesReturned < headerSize)
        {
            io.ok = false;
            io.win32Error = ERROR_INSUFFICIENT_BUFFER;
            io.message = std::string(operationName) + " response too small, bytesReturned=" + std::to_string(io.bytesReturned);
            return 0U;
        }
        if (entrySize == 0U || entrySize < minimumEntrySize)
        {
            io.ok = false;
            io.win32Error = ERROR_INVALID_DATA;
            io.message = std::string(operationName) + " entrySize invalid, entrySize=" + std::to_string(entrySize);
            return 0U;
        }

        const std::size_t kAvailableRows = (io.bytesReturned - headerSize) / static_cast<std::size_t>(entrySize);
        return std::min<std::size_t>(static_cast<std::size_t>(returnedCount), kAvailableRows);
    }

    // appendAuditSummary:
    // - Input: operation name, total count, returned count, parsed count, and byte count;
    // - Processing: generate a unified success diagnostic string.
    // - Returns: std::string, which can be written directly to IoResult::message.
    std::string appendAuditSummary(
        const char* const operationName,
        const std::uint32_t totalCount,
        const std::uint32_t returnedCount,
        const std::size_t parsedCount,
        const unsigned long bytesReturned)
    {
        std::ostringstream stream;
        stream << operationName
            << " total=" << totalCount
            << ", returned=" << returnedCount
            << ", parsed=" << parsedCount
            << ", bytesReturned=" << bytesReturned;
        return stream.str();
    }

    // copyAuditWideToFixed:
    // - Input: Target fixed-width wide character array, capacity, and R3 string;
    // - Processing: zero-initialize, truncate copy, and ensure NUL termination;
    // - Returns: Nothing.
    void copyAuditWideToFixed(wchar_t* const destination, const std::size_t destinationChars, const std::wstring& source)
    {
        if (destination == nullptr || destinationChars == 0U)
        {
            return;
        }

        std::fill(destination, destination + destinationChars, L'\0');
        const std::size_t kCopyChars = std::min<std::size_t>(source.size(), destinationChars - 1U);
        if (kCopyChars != 0U)
        {
            std::copy(source.data(), source.data() + static_cast<std::ptrdiff_t>(kCopyChars), destination);
        }
    }
}

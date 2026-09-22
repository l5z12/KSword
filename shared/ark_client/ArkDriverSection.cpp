#include "ArkDriverClient.h"

#include <algorithm>
#include <cstdint>
#include <sstream>
#include <string>
#include <vector>

namespace ksword::ark
{
    ProcessSectionQueryResult DriverClient::queryProcessSection(
        const std::uint32_t processId,
        const unsigned long flags,
        const unsigned long maxMappings) const
    {
        // Purpose: Invoke R0 process SectionObject / ControlArea query.
        // Processing: Input only PID, not SectionObject or ControlArea addresses, to prevent turning diagnostic addresses into credentials.
        // Returns: ProcessSectionQueryResult containing the mapping summary and DynData offset diagnostics.
        ProcessSectionQueryResult queryResult{};
        KSWORD_ARK_QUERY_PROCESS_SECTION_REQUEST request{};
        request.flags = flags;
        request.processId = processId;
        request.maxMappings = maxMappings;

        std::vector<std::uint8_t> responseBuffer(
            sizeof(KSWORD_ARK_QUERY_PROCESS_SECTION_RESPONSE) +
            (static_cast<std::size_t>(std::max<unsigned long>(maxMappings, 1UL)) * sizeof(KSWORD_ARK_SECTION_MAPPING_ENTRY)),
            0U);
        queryResult.io = deviceIoControl(
            IOCTL_KSWORD_ARK_QUERY_PROCESS_SECTION,
            &request,
            static_cast<unsigned long>(sizeof(request)),
            responseBuffer.data(),
            static_cast<unsigned long>(responseBuffer.size()));
        if (!queryResult.io.ok)
        {
            queryResult.io.message =
                "DeviceIoControl(IOCTL_KSWORD_ARK_QUERY_PROCESS_SECTION) failed, error=" +
                std::to_string(queryResult.io.win32Error);
            return queryResult;
        }

        constexpr std::size_t kHeaderSize =
            sizeof(KSWORD_ARK_QUERY_PROCESS_SECTION_RESPONSE) - sizeof(KSWORD_ARK_SECTION_MAPPING_ENTRY);
        if (queryResult.io.bytesReturned < kHeaderSize)
        {
            queryResult.io.ok = false;
            queryResult.io.message =
                "query-process-section response too small, bytesReturned=" +
                std::to_string(queryResult.io.bytesReturned);
            return queryResult;
        }

        const auto* responseHeader =
            reinterpret_cast<const KSWORD_ARK_QUERY_PROCESS_SECTION_RESPONSE*>(responseBuffer.data());
        if (responseHeader->entrySize < sizeof(KSWORD_ARK_SECTION_MAPPING_ENTRY))
        {
            queryResult.io.ok = false;
            queryResult.io.message =
                "query-process-section entry size invalid, entrySize=" +
                std::to_string(responseHeader->entrySize);
            return queryResult;
        }

        queryResult.version = static_cast<std::uint32_t>(responseHeader->version);
        queryResult.totalCount = static_cast<std::uint32_t>(responseHeader->totalCount);
        queryResult.returnedCount = static_cast<std::uint32_t>(responseHeader->returnedCount);
        queryResult.processId = static_cast<std::uint32_t>(responseHeader->processId);
        queryResult.fieldFlags = static_cast<std::uint32_t>(responseHeader->fieldFlags);
        queryResult.queryStatus = static_cast<std::uint32_t>(responseHeader->queryStatus);
        queryResult.lastStatus = static_cast<long>(responseHeader->lastStatus);
        queryResult.sectionObjectAddress = static_cast<std::uint64_t>(responseHeader->sectionObjectAddress);
        queryResult.controlAreaAddress = static_cast<std::uint64_t>(responseHeader->controlAreaAddress);
        queryResult.dynDataCapabilityMask = static_cast<std::uint64_t>(responseHeader->dynDataCapabilityMask);
        queryResult.epSectionObjectOffset = static_cast<std::uint32_t>(responseHeader->epSectionObjectOffset);
        queryResult.mmSectionControlAreaOffset = static_cast<std::uint32_t>(responseHeader->mmSectionControlAreaOffset);
        queryResult.mmControlAreaListHeadOffset = static_cast<std::uint32_t>(responseHeader->mmControlAreaListHeadOffset);
        queryResult.mmControlAreaLockOffset = static_cast<std::uint32_t>(responseHeader->mmControlAreaLockOffset);

        const std::size_t kAvailableCount =
            (queryResult.io.bytesReturned - kHeaderSize) /
            static_cast<std::size_t>(responseHeader->entrySize);
        const std::size_t kParsedCount = std::min<std::size_t>(
            static_cast<std::size_t>(responseHeader->returnedCount),
            kAvailableCount);
        queryResult.mappings.reserve(kParsedCount);
        for (std::size_t index = 0; index < kParsedCount; ++index)
        {
            const std::size_t kEntryOffset =
                kHeaderSize + (index * static_cast<std::size_t>(responseHeader->entrySize));
            const auto* entry =
                reinterpret_cast<const KSWORD_ARK_SECTION_MAPPING_ENTRY*>(responseBuffer.data() + kEntryOffset);
            SectionMappingEntry parsedEntry{};
            parsedEntry.viewMapType = static_cast<std::uint32_t>(entry->viewMapType);
            parsedEntry.processId = static_cast<std::uint32_t>(entry->processId);
            parsedEntry.startVa = static_cast<std::uint64_t>(entry->startVa);
            parsedEntry.endVa = static_cast<std::uint64_t>(entry->endVa);
            queryResult.mappings.push_back(parsedEntry);
        }

        std::ostringstream stream;
        stream << "version=" << queryResult.version
            << ", pid=" << queryResult.processId
            << ", status=" << queryResult.queryStatus
            << ", total=" << queryResult.totalCount
            << ", returned=" << queryResult.returnedCount
            << ", parsed=" << queryResult.mappings.size()
            << ", fieldFlags=0x" << std::hex << std::uppercase << queryResult.fieldFlags
            << ", lastStatus=0x" << static_cast<unsigned long>(static_cast<std::uint32_t>(queryResult.lastStatus))
            << std::dec << ", bytesReturned=" << queryResult.io.bytesReturned;
        queryResult.io.message = stream.str();
        return queryResult;
    }

    FileSectionMappingsQueryResult DriverClient::queryFileSectionMappings(
        const std::wstring& ntPath,
        const unsigned long flags,
        const unsigned long maxMappings) const
    {
        // Purpose: Invoke R0 file Data/Image ControlArea mapping reverse lookup.
        // Handling: R3 passes only the NT path; the driver is responsible for opening the FILE_OBJECT to avoid R3 passing kernel addresses.
        // Returns: result containing the list of mapping processes, ControlArea diagnostic address, and DynData offset.
        FileSectionMappingsQueryResult queryResult{};
        if (ntPath.empty() || ntPath.size() >= KSWORD_ARK_FILE_SECTION_PATH_MAX_CHARS)
        {
            queryResult.io.ok = false;
            queryResult.io.win32Error = ERROR_INVALID_PARAMETER;
            queryResult.io.message = "file-section path invalid, chars=" + std::to_string(ntPath.size());
            return queryResult;
        }

        KSWORD_ARK_QUERY_FILE_SECTION_MAPPINGS_REQUEST request{};
        request.flags = flags;
        request.maxMappings = maxMappings;
        request.pathLengthChars = static_cast<unsigned short>(ntPath.size());
        std::copy(ntPath.begin(), ntPath.end(), request.path);
        request.path[request.pathLengthChars] = L'\0';

        std::vector<std::uint8_t> responseBuffer(
            sizeof(KSWORD_ARK_QUERY_FILE_SECTION_MAPPINGS_RESPONSE) +
            (static_cast<std::size_t>(std::max<unsigned long>(maxMappings, 1UL)) * sizeof(KSWORD_ARK_FILE_SECTION_MAPPING_ENTRY)),
            0U);
        queryResult.io = deviceIoControl(
            IOCTL_KSWORD_ARK_QUERY_FILE_SECTION_MAPPINGS,
            &request,
            static_cast<unsigned long>(sizeof(request)),
            responseBuffer.data(),
            static_cast<unsigned long>(responseBuffer.size()));
        if (!queryResult.io.ok)
        {
            queryResult.io.message =
                "DeviceIoControl(IOCTL_KSWORD_ARK_QUERY_FILE_SECTION_MAPPINGS) failed, error=" +
                std::to_string(queryResult.io.win32Error);
            return queryResult;
        }

        constexpr std::size_t kHeaderSize =
            sizeof(KSWORD_ARK_QUERY_FILE_SECTION_MAPPINGS_RESPONSE) - sizeof(KSWORD_ARK_FILE_SECTION_MAPPING_ENTRY);
        if (queryResult.io.bytesReturned < kHeaderSize)
        {
            queryResult.io.ok = false;
            queryResult.io.message =
                "query-file-section response too small, bytesReturned=" +
                std::to_string(queryResult.io.bytesReturned);
            return queryResult;
        }

        const auto* responseHeader =
            reinterpret_cast<const KSWORD_ARK_QUERY_FILE_SECTION_MAPPINGS_RESPONSE*>(responseBuffer.data());
        if (responseHeader->entrySize < sizeof(KSWORD_ARK_FILE_SECTION_MAPPING_ENTRY))
        {
            queryResult.io.ok = false;
            queryResult.io.message =
                "query-file-section entry size invalid, entrySize=" +
                std::to_string(responseHeader->entrySize);
            return queryResult;
        }

        queryResult.version = static_cast<std::uint32_t>(responseHeader->version);
        queryResult.totalCount = static_cast<std::uint32_t>(responseHeader->totalCount);
        queryResult.returnedCount = static_cast<std::uint32_t>(responseHeader->returnedCount);
        queryResult.fieldFlags = static_cast<std::uint32_t>(responseHeader->fieldFlags);
        queryResult.queryStatus = static_cast<std::uint32_t>(responseHeader->queryStatus);
        queryResult.lastStatus = static_cast<long>(responseHeader->lastStatus);
        queryResult.fileObjectAddress = static_cast<std::uint64_t>(responseHeader->fileObjectAddress);
        queryResult.sectionObjectPointersAddress = static_cast<std::uint64_t>(responseHeader->sectionObjectPointersAddress);
        queryResult.dataControlAreaAddress = static_cast<std::uint64_t>(responseHeader->dataControlAreaAddress);
        queryResult.imageControlAreaAddress = static_cast<std::uint64_t>(responseHeader->imageControlAreaAddress);
        queryResult.dynDataCapabilityMask = static_cast<std::uint64_t>(responseHeader->dynDataCapabilityMask);
        queryResult.mmControlAreaListHeadOffset = static_cast<std::uint32_t>(responseHeader->mmControlAreaListHeadOffset);
        queryResult.mmControlAreaLockOffset = static_cast<std::uint32_t>(responseHeader->mmControlAreaLockOffset);

        const std::size_t kAvailableCount =
            (queryResult.io.bytesReturned - kHeaderSize) /
            static_cast<std::size_t>(responseHeader->entrySize);
        const std::size_t kParsedCount = std::min<std::size_t>(
            static_cast<std::size_t>(responseHeader->returnedCount),
            kAvailableCount);
        queryResult.mappings.reserve(kParsedCount);
        for (std::size_t index = 0; index < kParsedCount; ++index)
        {
            const std::size_t kEntryOffset =
                kHeaderSize + (index * static_cast<std::size_t>(responseHeader->entrySize));
            const auto* entry =
                reinterpret_cast<const KSWORD_ARK_FILE_SECTION_MAPPING_ENTRY*>(responseBuffer.data() + kEntryOffset);
            FileSectionMappingEntry parsedEntry{};
            parsedEntry.sectionKind = static_cast<std::uint32_t>(entry->sectionKind);
            parsedEntry.viewMapType = static_cast<std::uint32_t>(entry->viewMapType);
            parsedEntry.processId = static_cast<std::uint32_t>(entry->processId);
            parsedEntry.controlAreaAddress = static_cast<std::uint64_t>(entry->controlAreaAddress);
            parsedEntry.startVa = static_cast<std::uint64_t>(entry->startVa);
            parsedEntry.endVa = static_cast<std::uint64_t>(entry->endVa);
            queryResult.mappings.push_back(parsedEntry);
        }

        std::ostringstream stream;
        stream << "version=" << queryResult.version
            << ", status=" << queryResult.queryStatus
            << ", total=" << queryResult.totalCount
            << ", returned=" << queryResult.returnedCount
            << ", parsed=" << queryResult.mappings.size()
            << ", fieldFlags=0x" << std::hex << std::uppercase << queryResult.fieldFlags
            << ", lastStatus=0x" << static_cast<unsigned long>(static_cast<std::uint32_t>(queryResult.lastStatus))
            << std::dec << ", bytesReturned=" << queryResult.io.bytesReturned;
        queryResult.io.message = stream.str();
        return queryResult;
    }
}

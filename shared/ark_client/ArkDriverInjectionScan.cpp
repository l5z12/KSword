#include "ArkDriverClient.h"

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

namespace ksword::ark
{
    namespace
    {
        // Response buffer upper limit. VAD entries are 56 bytes each and PTE segments are 48 bytes each; the worst-case scenarios
        // calculated based on their respective entry limits are both in the 1 MiB range. We reserve 2 MiB as the ceiling.
        constexpr std::size_t kMaxInjectionResponseBytes = 2U * 1024U * 1024U;

        template <typename Header, typename Entry>
        bool validateVariableResponse(
            const std::vector<std::uint8_t>& buffer,
            const unsigned long bytesReturned,
            const std::size_t headerSize,
            IoResult& io,
            const char* label,
            const Header*& headerOut,
            std::size_t& availableEntriesOut)
        {
            headerOut = nullptr;
            availableEntriesOut = 0U;
            if (bytesReturned < headerSize)
            {
                io.ok = false;
                io.message = std::string(label) + " response too small, bytesReturned=" +
                             std::to_string(bytesReturned);
                return false;
            }
            const auto* header = reinterpret_cast<const Header*>(buffer.data());
            if (header->entrySize < sizeof(Entry))
            {
                io.ok = false;
                io.message = std::string(label) + " entry size invalid, entrySize=" +
                             std::to_string(header->entrySize);
                return false;
            }
            // Entry count is based on **actual returned bytes**, not returnedCount: if the driver
            // reports an inflated count, it would cause an out-of-bounds read into its own buffer.
            availableEntriesOut =
                (static_cast<std::size_t>(bytesReturned) - headerSize) / header->entrySize;
            headerOut = header;
            return true;
        }
    }

    ProcessVadEnumResult DriverClient::enumerateProcessVad(
        const std::uint32_t processId,
        const std::uint64_t startAddress,
        const std::uint64_t endAddress,
        const std::uint64_t cursorVpn,
        const unsigned long maxEntries,
        const unsigned long flags) const
    {
        // Purpose: enumerate the target process's VAD tree, providing an independent view beyond R3 VirtualQueryEx.
        // Processing: Input contains only PID and range/cursor; the driver accepts no kernel addresses as credentials.
        // Returns: ProcessVadEnumResult; if profileVerified is 0, the result cannot be used for missing item inference.
        ProcessVadEnumResult result{};
        KSWORD_ARK_ENUMERATE_PROCESS_VAD_REQUEST request{};
        request.flags = flags;
        request.processId = processId;
        request.maxEntries = maxEntries;
        request.startAddress = startAddress;
        request.endAddress = endAddress;
        request.cursorVpn = cursorVpn;

        const unsigned long kBoundedEntries =
            std::min<unsigned long>(
                std::max<unsigned long>(maxEntries, 1UL),
                KSWORD_ARK_INJECTION_VAD_LIMIT_MAX);
        std::size_t bufferBytes =
            KSWORD_ARK_INJECTION_VAD_RESPONSE_HEADER_SIZE +
            (static_cast<std::size_t>(kBoundedEntries) * sizeof(KSWORD_ARK_PROCESS_VAD_ENTRY));
        bufferBytes = std::min(bufferBytes, kMaxInjectionResponseBytes);

        std::vector<std::uint8_t> responseBuffer(bufferBytes, 0U);
        result.io = deviceIoControl(
            IOCTL_KSWORD_ARK_ENUMERATE_PROCESS_VAD,
            &request,
            static_cast<unsigned long>(sizeof(request)),
            responseBuffer.data(),
            static_cast<unsigned long>(responseBuffer.size()));
        if (!result.io.ok)
        {
            result.io.message =
                "DeviceIoControl(IOCTL_KSWORD_ARK_ENUMERATE_PROCESS_VAD) failed, error=" +
                std::to_string(result.io.win32Error);
            return result;
        }

        const KSWORD_ARK_ENUMERATE_PROCESS_VAD_RESPONSE* header = nullptr;
        std::size_t available = 0U;
        if (!validateVariableResponse<
                KSWORD_ARK_ENUMERATE_PROCESS_VAD_RESPONSE,
                KSWORD_ARK_PROCESS_VAD_ENTRY>(
                responseBuffer,
                result.io.bytesReturned,
                KSWORD_ARK_INJECTION_VAD_RESPONSE_HEADER_SIZE,
                result.io,
                "enumerate-process-vad",
                header,
                available))
        {
            return result;
        }

        result.version = static_cast<std::uint32_t>(header->version);
        result.processId = static_cast<std::uint32_t>(header->processId);
        result.fieldFlags = static_cast<std::uint32_t>(header->fieldFlags);
        result.status = static_cast<std::uint32_t>(header->status);
        result.lastStatus = header->lastStatus;
        result.returnedCount = static_cast<std::uint32_t>(header->returnedCount);
        result.visitedCount = static_cast<std::uint32_t>(header->visitedCount);
        result.unreadableNodeCount = static_cast<std::uint32_t>(header->unreadableNodeCount);
        result.profileVerified = static_cast<std::uint32_t>(header->profileVerified);
        result.vadRootOffset = static_cast<std::uint32_t>(header->vadRootOffset);
        result.vadRootAddress = header->vadRootAddress;
        result.nextCursorVpn = header->nextCursorVpn;
        result.integrityValid =
            (header->fieldFlags & KSWORD_ARK_INJECTION_FIELD_INTEGRITY_VALID) != 0UL;
        result.vadCountKnown =
            (header->fieldFlags & KSWORD_ARK_INJECTION_FIELD_VAD_COUNT_PRESENT) != 0UL;
        result.vadHintKnown =
            (header->fieldFlags & KSWORD_ARK_INJECTION_FIELD_VAD_HINT_PRESENT) != 0UL;
        result.vadCount = static_cast<std::uint32_t>(header->vadCount);
        result.parentMismatchNodes =
            static_cast<std::uint32_t>(header->parentMismatchNodes);
        result.vadHintVisited = header->vadHintVisited != 0UL;
        result.vadHintAddress = header->vadHintAddress;

        const std::size_t kParsed =
            std::min<std::size_t>(available, static_cast<std::size_t>(header->returnedCount));
        result.entries.reserve(kParsed);
        for (std::size_t i = 0; i < kParsed; ++i)
        {
            const auto* raw = reinterpret_cast<const KSWORD_ARK_PROCESS_VAD_ENTRY*>(
                responseBuffer.data() + KSWORD_ARK_INJECTION_VAD_RESPONSE_HEADER_SIZE +
                (i * header->entrySize));
            ProcessVadEntry entry{};
            entry.startVa = raw->startVa;
            entry.endVaExclusive = raw->endVaExclusive;
            entry.vadNodeAddress = raw->vadNodeAddress;
            entry.subsection = raw->subsection;
            entry.firstPrototypePte = raw->firstPrototypePte;
            entry.vadFlagsRaw = static_cast<std::uint32_t>(raw->vadFlagsRaw);
            entry.protection = static_cast<std::uint32_t>(raw->protection);
            entry.vadType = static_cast<std::uint32_t>(raw->vadType);
            entry.entryFlags = static_cast<std::uint32_t>(raw->entryFlags);
            result.entries.push_back(entry);
        }
        return result;
    }

    ProcessExecutablePteScanResult DriverClient::scanProcessExecutablePte(
        const std::uint32_t processId,
        const std::uint64_t startAddress,
        const std::uint64_t endAddress,
        const std::uint64_t cursorAddress,
        const unsigned long maxEntries,
        const unsigned long maxTableReads,
        const unsigned long flags) const
    {
        // Purpose: Perform range scanning on the target process page tables and report user-mode executable leaf pages.
        // Processing: This is the view of how the processor actually sees it, independent of VAD/VirtualQueryEx protection attributes.
        // Return: ProcessExecutablePteScanResult. Use nextCursorAddress to resume scanning when TRUNCATED.
        ProcessExecutablePteScanResult result{};
        KSWORD_ARK_SCAN_PROCESS_EXECUTABLE_PTE_REQUEST request{};
        request.flags = flags;
        request.processId = processId;
        request.maxEntries = maxEntries;
        request.maxTableReads = maxTableReads;
        request.startAddress = startAddress;
        request.endAddress = endAddress;
        request.cursorAddress = cursorAddress;

        const unsigned long kBoundedEntries =
            std::min<unsigned long>(
                std::max<unsigned long>(maxEntries, 1UL),
                KSWORD_ARK_INJECTION_PTE_LIMIT_MAX);
        std::size_t bufferBytes =
            KSWORD_ARK_INJECTION_PTE_RESPONSE_HEADER_SIZE +
            (static_cast<std::size_t>(kBoundedEntries) *
             sizeof(KSWORD_ARK_PROCESS_EXECUTABLE_PTE_ENTRY));
        bufferBytes = std::min(bufferBytes, kMaxInjectionResponseBytes);

        std::vector<std::uint8_t> responseBuffer(bufferBytes, 0U);
        result.io = deviceIoControl(
            IOCTL_KSWORD_ARK_SCAN_PROCESS_EXECUTABLE_PTE,
            &request,
            static_cast<unsigned long>(sizeof(request)),
            responseBuffer.data(),
            static_cast<unsigned long>(responseBuffer.size()));
        if (!result.io.ok)
        {
            result.io.message =
                "DeviceIoControl(IOCTL_KSWORD_ARK_SCAN_PROCESS_EXECUTABLE_PTE) failed, error=" +
                std::to_string(result.io.win32Error);
            return result;
        }

        const KSWORD_ARK_SCAN_PROCESS_EXECUTABLE_PTE_RESPONSE* header = nullptr;
        std::size_t available = 0U;
        if (!validateVariableResponse<
                KSWORD_ARK_SCAN_PROCESS_EXECUTABLE_PTE_RESPONSE,
                KSWORD_ARK_PROCESS_EXECUTABLE_PTE_ENTRY>(
                responseBuffer,
                result.io.bytesReturned,
                KSWORD_ARK_INJECTION_PTE_RESPONSE_HEADER_SIZE,
                result.io,
                "scan-process-executable-pte",
                header,
                available))
        {
            return result;
        }

        result.version = static_cast<std::uint32_t>(header->version);
        result.processId = static_cast<std::uint32_t>(header->processId);
        result.fieldFlags = static_cast<std::uint32_t>(header->fieldFlags);
        result.status = static_cast<std::uint32_t>(header->status);
        result.lastStatus = header->lastStatus;
        result.returnedCount = static_cast<std::uint32_t>(header->returnedCount);
        result.tableReads = static_cast<std::uint32_t>(header->tableReads);
        result.failedTableReads = static_cast<std::uint32_t>(header->failedTableReads);
        result.executablePageCount = static_cast<std::uint32_t>(header->executablePageCount);
        result.scannedBegin = header->scannedBegin;
        result.scannedEnd = header->scannedEnd;
        result.nextCursorAddress = header->nextCursorAddress;
        result.cr3PhysicalAddress = header->cr3PhysicalAddress;

        const std::size_t kParsed =
            std::min<std::size_t>(available, static_cast<std::size_t>(header->returnedCount));
        result.entries.reserve(kParsed);
        for (std::size_t i = 0; i < kParsed; ++i)
        {
            const auto* raw =
                reinterpret_cast<const KSWORD_ARK_PROCESS_EXECUTABLE_PTE_ENTRY*>(
                    responseBuffer.data() + KSWORD_ARK_INJECTION_PTE_RESPONSE_HEADER_SIZE +
                    (i * header->entrySize));
            ProcessExecutablePteEntry entry{};
            entry.startVa = raw->startVa;
            entry.byteLength = raw->byteLength;
            entry.firstPhysicalAddress = raw->firstPhysicalAddress;
            entry.firstEntryValue = raw->firstEntryValue;
            entry.pageSize = static_cast<std::uint32_t>(raw->pageSize);
            entry.pageCount = static_cast<std::uint32_t>(raw->pageCount);
            entry.effectiveFlags = static_cast<std::uint32_t>(raw->effectiveFlags);
            entry.entryFlags = static_cast<std::uint32_t>(raw->entryFlags);
            result.entries.push_back(entry);
        }
        return result;
    }

    ImageSectionPagesResult DriverClient::readImageSectionPages(
        const std::uint32_t processId,
        const std::uint64_t rangeStart,
        const std::uint64_t rangeEnd,
        const std::uint64_t cursorVa,
        const unsigned long maxPages,
        const unsigned long flags) const
    {
        ImageSectionPagesResult result{};

        const bool kIncludeBytes =
            (flags & KSWORD_ARK_INJECTION_SECTION_FLAG_INCLUDE_BYTES) != 0UL;
        unsigned long pages = maxPages != 0UL
            ? maxPages
            : KSWORD_ARK_INJECTION_SECTION_PAGES_DEFAULT;
        if (kIncludeBytes && pages > KSWORD_ARK_INJECTION_SECTION_BYTES_PAGES_MAX)
        {
            pages = KSWORD_ARK_INJECTION_SECTION_BYTES_PAGES_MAX;
        }
        if (pages > KSWORD_ARK_INJECTION_SECTION_PAGES_MAX)
        {
            pages = KSWORD_ARK_INJECTION_SECTION_PAGES_MAX;
        }

        KSWORD_ARK_READ_IMAGE_SECTION_PAGES_REQUEST request{};
        request.size = static_cast<unsigned long>(sizeof(request));
        request.version = KSWORD_ARK_INJECTION_SCAN_PROTOCOL_VERSION;
        request.processId = processId;
        request.flags = flags;
        request.rangeStart = rangeStart;
        request.rangeEnd = rangeEnd;
        request.maxPages = pages;
        request.cursorVa = cursorVa;

        // Buffer must be large enough to hold all entries plus optional page bytes; otherwise the driver truncates based on
        // buffer capacity, causing the caller to see 'missing pages' due to insufficient buffer rather than missing references.
        const std::size_t kPerPage =
            sizeof(KSWORD_ARK_IMAGE_SECTION_PAGE_ENTRY) + (kIncludeBytes ? 4096U : 0U);
        std::size_t responseBytes =
            KSWORD_ARK_INJECTION_SECTION_RESPONSE_HEADER_SIZE +
            (static_cast<std::size_t>(pages) * kPerPage);
        if (responseBytes > kMaxInjectionResponseBytes)
        {
            responseBytes = kMaxInjectionResponseBytes;
        }
        std::vector<std::uint8_t> responseBuffer(responseBytes, 0U);

        result.io = deviceIoControl(
            IOCTL_KSWORD_ARK_READ_IMAGE_SECTION_PAGES,
            &request,
            static_cast<unsigned long>(sizeof(request)),
            responseBuffer.data(),
            static_cast<unsigned long>(responseBuffer.size()));
        if (!result.io.ok)
        {
            result.io.message =
                "DeviceIoControl(IOCTL_KSWORD_ARK_READ_IMAGE_SECTION_PAGES) failed, error=" +
                std::to_string(result.io.win32Error);
            return result;
        }

        const KSWORD_ARK_READ_IMAGE_SECTION_PAGES_RESPONSE* header = nullptr;
        std::size_t available = 0U;
        if (!validateVariableResponse<
                KSWORD_ARK_READ_IMAGE_SECTION_PAGES_RESPONSE,
                KSWORD_ARK_IMAGE_SECTION_PAGE_ENTRY>(
                responseBuffer,
                result.io.bytesReturned,
                KSWORD_ARK_INJECTION_SECTION_RESPONSE_HEADER_SIZE,
                result.io,
                "read-image-section-pages",
                header,
                available))
        {
            return result;
        }

        result.version = static_cast<std::uint32_t>(header->version);
        result.processId = static_cast<std::uint32_t>(header->processId);
        result.fieldFlags = static_cast<std::uint32_t>(header->fieldFlags);
        result.status = static_cast<std::uint32_t>(header->status);
        result.lastStatus = header->lastStatus;
        result.returnedCount = static_cast<std::uint32_t>(header->returnedCount);
        result.validPageCount = static_cast<std::uint32_t>(header->validPageCount);
        result.notResidentPageCount = static_cast<std::uint32_t>(header->notResidentPageCount);
        result.unreadablePteCount = static_cast<std::uint32_t>(header->unreadablePteCount);
        result.bytesPerPage = static_cast<std::uint32_t>(header->bytesPerPage);
        result.controlArea = header->controlArea;
        result.segment = header->segment;
        result.prototypePteArray = header->prototypePteArray;
        result.nextCursorVa = header->nextCursorVa;

        const std::size_t kParsed =
            std::min<std::size_t>(available, static_cast<std::size_t>(header->returnedCount));
        result.entries.reserve(kParsed);
        for (std::size_t i = 0; i < kParsed; ++i)
        {
            const auto* entry = reinterpret_cast<const KSWORD_ARK_IMAGE_SECTION_PAGE_ENTRY*>(
                responseBuffer.data() + KSWORD_ARK_INJECTION_SECTION_RESPONSE_HEADER_SIZE +
                (i * header->entrySize));
            ImageSectionPageEntry row;
            row.va = entry->va;
            row.prototypePteAddress = entry->prototypePteAddress;
            row.prototypePteValue = entry->prototypePteValue;
            row.physicalAddress = entry->physicalAddress;
            row.entryFlags = static_cast<std::uint32_t>(entry->entryFlags);
            result.entries.push_back(row);
        }

        if (kIncludeBytes && header->bytesPerPage != 0UL && header->validPageCount != 0UL)
        {
            // The byte area uses the **response-provided** byteAreaOffset. Calculating it
            // independently is incorrect—it depends on the driver-side entry capacity, which is
            // constrained by both buffer size and maxPages, while the caller only knows the former.
            const std::size_t kByteOffset = static_cast<std::size_t>(header->byteAreaOffset);
            const std::size_t kByteCount =
                static_cast<std::size_t>(header->validPageCount) * header->bytesPerPage;
            if (kByteOffset + kByteCount <= result.io.bytesReturned)
            {
                result.pageBytes.assign(responseBuffer.begin() + kByteOffset,
                                        responseBuffer.begin() + kByteOffset + kByteCount);
            }
            else
            {
                result.io.message = "read-image-section-pages byte area truncated";
            }
        }
        return result;
    }
}

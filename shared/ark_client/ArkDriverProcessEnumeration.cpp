#include "ArkDriverClient.h"
#include "ArkDriverResponseSupport.h"

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <sstream>
#include <utility>
#include <vector>
#include "../platform/string/String.h"

namespace ksword::ark
{
    using detail::isUnsupportedIoctlError;
    namespace
    {

        std::string fixedUtf16ToUtf8String(const unsigned short* textBuffer, const std::size_t maxChars)
        {
            // textBuffer usage: receives UTF-16 code unit arrays from the shared protocol.
            // maxChars usage: limits the maximum scan length to prevent out-of-bounds access when a trailing NUL is missing.
            if (textBuffer == nullptr || maxChars == 0U)
            {
                return {};
            }

            std::size_t length = 0U;
            while (length < maxChars && textBuffer[length] != 0U)
            {
                ++length;
            }
            if (length == 0U)
            {
                return {};
            }

            std::wstring wideText;
            wideText.reserve(length);
            for (std::size_t index = 0; index < length; ++index)
            {
                wideText.push_back(static_cast<wchar_t>(textBuffer[index]));
            }
            return ks::str::utf16ToUtf8(wideText);
        }
    }

    ProcessEnumResult DriverClient::enumerateProcesses(const unsigned long flags) const
    {
        return enumerateProcesses(flags, nullptr);
    }

    ProcessEnumResult DriverClient::enumerateProcesses(
        const unsigned long flags,
        DriverHandle* const existingHandle) const
    {
        ProcessEnumResult enumResult{};
        KSWORD_ARK_ENUM_PROCESS_REQUEST request{};
        request.flags = flags;

        std::vector<std::uint8_t> responseBuffer(1024U * 1024U, 0U);
        enumResult.io = deviceIoControl(
            IOCTL_KSWORD_ARK_ENUM_PROCESS,
            &request,
            static_cast<unsigned long>(sizeof(request)),
            responseBuffer.data(),
            static_cast<unsigned long>(responseBuffer.size()),
            existingHandle);
        if (!enumResult.io.ok)
        {
            enumResult.io.message = "DeviceIoControl(IOCTL_KSWORD_ARK_ENUM_PROCESS) failed, error=" + std::to_string(enumResult.io.win32Error);
            return enumResult;
        }

        constexpr std::size_t kHeaderSize = sizeof(KSWORD_ARK_ENUM_PROCESS_RESPONSE) - sizeof(KSWORD_ARK_PROCESS_ENTRY);
        if (enumResult.io.bytesReturned < kHeaderSize)
        {
            enumResult.io.ok = false;
            enumResult.io.message = "enum-process response too small, bytesReturned=" + std::to_string(enumResult.io.bytesReturned);
            return enumResult;
        }

        const auto* responseHeader = reinterpret_cast<const KSWORD_ARK_ENUM_PROCESS_RESPONSE*>(responseBuffer.data());
        // v1MinimumEntrySize purpose:
        // - Only require the legacy protocol's fixed header fields to be complete, ensuring protocol v1 drivers remain parsable.
        // - imageName length comes from protocol constants to avoid compiler differences on null pointer member expressions.
        constexpr std::size_t kV1MinimumEntrySize =
            sizeof(unsigned long) * 4U + 16U;
        if (responseHeader->entrySize < kV1MinimumEntrySize)
        {
            enumResult.io.ok = false;
            enumResult.io.message = "enum-process entry size invalid, entrySize=" + std::to_string(responseHeader->entrySize);
            return enumResult;
        }

        enumResult.version = responseHeader->version;
        enumResult.totalCount = responseHeader->totalCount;
        enumResult.returnedCount = responseHeader->returnedCount;
        const std::size_t kAvailableCount = (enumResult.io.bytesReturned - kHeaderSize) / static_cast<std::size_t>(responseHeader->entrySize);
        const std::size_t kParsedCount = std::min<std::size_t>(static_cast<std::size_t>(responseHeader->returnedCount), kAvailableCount);
        enumResult.entries.reserve(kParsedCount);
        for (std::size_t index = 0; index < kParsedCount; ++index)
        {
            const std::size_t kEntryOffset = kHeaderSize + (index * static_cast<std::size_t>(responseHeader->entrySize));
            const auto* entry = reinterpret_cast<const KSWORD_ARK_PROCESS_ENTRY*>(responseBuffer.data() + kEntryOffset);
            ProcessEntry parsedEntry{};
            parsedEntry.processId = static_cast<std::uint32_t>(entry->processId);
            parsedEntry.parentProcessId = static_cast<std::uint32_t>(entry->parentProcessId);
            parsedEntry.flags = static_cast<std::uint32_t>(entry->flags);
            parsedEntry.imageName = detail::readFixedString(entry->imageName, sizeof(entry->imageName));
            constexpr std::size_t kV2EntrySize = offsetof(
                KSWORD_ARK_PROCESS_ENTRY,
                creationTime100ns);
            if (responseHeader->entrySize >= kV2EntrySize)
            {
                parsedEntry.sessionId = static_cast<std::uint32_t>(entry->sessionId);
                parsedEntry.fieldFlags = static_cast<std::uint32_t>(entry->fieldFlags);
                parsedEntry.r0Status = static_cast<std::uint32_t>(entry->r0Status);
                parsedEntry.sessionSource = static_cast<std::uint32_t>(entry->sessionSource);
                parsedEntry.protection = static_cast<std::uint8_t>(entry->protection);
                parsedEntry.signatureLevel = static_cast<std::uint8_t>(entry->signatureLevel);
                parsedEntry.sectionSignatureLevel = static_cast<std::uint8_t>(entry->sectionSignatureLevel);
                parsedEntry.protectionSource = static_cast<std::uint32_t>(entry->protectionSource);
                parsedEntry.signatureLevelSource = static_cast<std::uint32_t>(entry->signatureLevelSource);
                parsedEntry.sectionSignatureLevelSource = static_cast<std::uint32_t>(entry->sectionSignatureLevelSource);
                parsedEntry.objectTableSource = static_cast<std::uint32_t>(entry->objectTableSource);
                parsedEntry.sectionObjectSource = static_cast<std::uint32_t>(entry->sectionObjectSource);
                parsedEntry.imagePathSource = static_cast<std::uint32_t>(entry->imagePathSource);
                parsedEntry.protectionOffset = static_cast<std::uint32_t>(entry->protectionOffset);
                parsedEntry.signatureLevelOffset = static_cast<std::uint32_t>(entry->signatureLevelOffset);
                parsedEntry.sectionSignatureLevelOffset = static_cast<std::uint32_t>(entry->sectionSignatureLevelOffset);
                parsedEntry.objectTableOffset = static_cast<std::uint32_t>(entry->objectTableOffset);
                parsedEntry.sectionObjectOffset = static_cast<std::uint32_t>(entry->sectionObjectOffset);
                parsedEntry.objectTableAddress = static_cast<std::uint64_t>(entry->objectTableAddress);
                parsedEntry.sectionObjectAddress = static_cast<std::uint64_t>(entry->sectionObjectAddress);
                parsedEntry.dynDataCapabilityMask = static_cast<std::uint64_t>(entry->dynDataCapabilityMask);
                parsedEntry.imagePath = fixedUtf16ToUtf8String(
                    entry->imagePath,
                    KSWORD_ARK_PROCESS_IMAGE_PATH_CHARS);
            }
            if (responseHeader->entrySize >= sizeof(KSWORD_ARK_PROCESS_ENTRY))
            {
                parsedEntry.creationTime100ns =
                    static_cast<std::uint64_t>(entry->creationTime100ns);
            }
            enumResult.entries.push_back(std::move(parsedEntry));
        }

        std::ostringstream stream;
        stream << "version=" << enumResult.version
            << ", total=" << enumResult.totalCount
            << ", returned=" << enumResult.returnedCount
            << ", parsed=" << enumResult.entries.size()
            << ", bytesReturned=" << enumResult.io.bytesReturned;
        enumResult.io.message = stream.str();
        return enumResult;
    }
}

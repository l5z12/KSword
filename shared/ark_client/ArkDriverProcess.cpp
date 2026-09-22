#include "ArkDriverClient.h"
#include "ArkDriverResponseSupport.h"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <sstream>
#include <utility>
#include <vector>

namespace ksword::ark
{
    namespace
    {
        constexpr std::size_t kProcessCrossViewHeaderSize =
            sizeof(KSWORD_ARK_PROCESS_CROSSVIEW_RESPONSE) -
            sizeof(KSWORD_ARK_PROCESS_CROSSVIEW_ROW);
        constexpr std::size_t kThreadCrossViewHeaderSize =
            sizeof(KSWORD_ARK_THREAD_CROSSVIEW_RESPONSE) -
            sizeof(KSWORD_ARK_THREAD_CROSSVIEW_ROW);



        CrossViewFieldOffsets copyCrossViewOffsets(const KSWORD_ARK_CROSSVIEW_FIELD_OFFSETS& source)
        {
            // Input: offset package from the shared protocol.
            // Processing: Copy field by field without interpreting whether offsets are available.
            // Return: CrossViewFieldOffsets on the R3 side.
            CrossViewFieldOffsets offsets{};
            offsets.epUniqueProcessId = static_cast<std::uint32_t>(source.epUniqueProcessId);
            offsets.epActiveProcessLinks = static_cast<std::uint32_t>(source.epActiveProcessLinks);
            offsets.epThreadListHead = static_cast<std::uint32_t>(source.epThreadListHead);
            offsets.epImageFileName = static_cast<std::uint32_t>(source.epImageFileName);
            offsets.etCid = static_cast<std::uint32_t>(source.etCid);
            offsets.etThreadListEntry = static_cast<std::uint32_t>(source.etThreadListEntry);
            offsets.etStartAddress = static_cast<std::uint32_t>(source.etStartAddress);
            offsets.etWin32StartAddress = static_cast<std::uint32_t>(source.etWin32StartAddress);
            offsets.ktProcess = static_cast<std::uint32_t>(source.ktProcess);
            offsets.htTableCode = static_cast<std::uint32_t>(source.htTableCode);
            offsets.hteLowValue = static_cast<std::uint32_t>(source.hteLowValue);
            offsets.pspCidTableRva = static_cast<std::uint32_t>(source.pspCidTableRva);
            offsets.pspCidTableAddress = static_cast<std::uint64_t>(source.pspCidTableAddress);
            offsets.epUniqueProcessIdSource = static_cast<std::uint32_t>(source.epUniqueProcessIdSource);
            offsets.epActiveProcessLinksSource = static_cast<std::uint32_t>(source.epActiveProcessLinksSource);
            offsets.epThreadListHeadSource = static_cast<std::uint32_t>(source.epThreadListHeadSource);
            offsets.epImageFileNameSource = static_cast<std::uint32_t>(source.epImageFileNameSource);
            offsets.etCidSource = static_cast<std::uint32_t>(source.etCidSource);
            offsets.etThreadListEntrySource = static_cast<std::uint32_t>(source.etThreadListEntrySource);
            offsets.etStartAddressSource = static_cast<std::uint32_t>(source.etStartAddressSource);
            offsets.etWin32StartAddressSource = static_cast<std::uint32_t>(source.etWin32StartAddressSource);
            offsets.ktProcessSource = static_cast<std::uint32_t>(source.ktProcessSource);
            offsets.htTableCodeSource = static_cast<std::uint32_t>(source.htTableCodeSource);
            offsets.hteLowValueSource = static_cast<std::uint32_t>(source.hteLowValueSource);
            offsets.pspCidTableSource = static_cast<std::uint32_t>(source.pspCidTableSource);
            return offsets;
        }
    }

    ThreadEnumResult DriverClient::enumerateThreads(
        const unsigned long flags,
        const std::uint32_t processId) const
    {
        ThreadEnumResult enumResult{};
        KSWORD_ARK_ENUM_THREAD_REQUEST request{};
        request.flags = flags;
        request.processId = processId;

        std::vector<std::uint8_t> responseBuffer(1024U * 1024U, 0U);
        enumResult.io = deviceIoControl(
            IOCTL_KSWORD_ARK_ENUM_THREAD,
            &request,
            static_cast<unsigned long>(sizeof(request)),
            responseBuffer.data(),
            static_cast<unsigned long>(responseBuffer.size()));
        if (!enumResult.io.ok)
        {
            enumResult.io.message =
                "DeviceIoControl(IOCTL_KSWORD_ARK_ENUM_THREAD) failed, error=" +
                std::to_string(enumResult.io.win32Error);
            return enumResult;
        }

        constexpr std::size_t kHeaderSize =
            sizeof(KSWORD_ARK_ENUM_THREAD_RESPONSE) - sizeof(KSWORD_ARK_THREAD_ENTRY);
        if (enumResult.io.bytesReturned < kHeaderSize)
        {
            enumResult.io.ok = false;
            enumResult.io.message =
                "enum-thread response too small, bytesReturned=" +
                std::to_string(enumResult.io.bytesReturned);
            return enumResult;
        }

        const auto* responseHeader =
            reinterpret_cast<const KSWORD_ARK_ENUM_THREAD_RESPONSE*>(responseBuffer.data());
        if (responseHeader->entrySize < sizeof(KSWORD_ARK_THREAD_ENTRY))
        {
            enumResult.io.ok = false;
            enumResult.io.message =
                "enum-thread entry size invalid, entrySize=" +
                std::to_string(responseHeader->entrySize);
            return enumResult;
        }

        enumResult.version = static_cast<std::uint32_t>(responseHeader->version);
        enumResult.totalCount = static_cast<std::uint32_t>(responseHeader->totalCount);
        enumResult.returnedCount = static_cast<std::uint32_t>(responseHeader->returnedCount);

        const std::size_t kAvailableCount =
            (enumResult.io.bytesReturned - kHeaderSize) /
            static_cast<std::size_t>(responseHeader->entrySize);
        const std::size_t kParsedCount = std::min<std::size_t>(
            static_cast<std::size_t>(responseHeader->returnedCount),
            kAvailableCount);
        enumResult.entries.reserve(kParsedCount);

        for (std::size_t index = 0; index < kParsedCount; ++index)
        {
            const std::size_t kEntryOffset =
                kHeaderSize + (index * static_cast<std::size_t>(responseHeader->entrySize));
            const auto* entry =
                reinterpret_cast<const KSWORD_ARK_THREAD_ENTRY*>(responseBuffer.data() + kEntryOffset);
            ThreadEntry parsedEntry{};

            // Copy thread identity and cross-view flags:
            // - threadId/processId are used to merge R3 thread pages by PID/TID;
            // - flags: retains markers distinguishing R0 active-thread walk from CID scan.
            parsedEntry.threadId = static_cast<std::uint32_t>(entry->threadId);
            parsedEntry.processId = static_cast<std::uint32_t>(entry->processId);
            parsedEntry.flags = static_cast<std::uint32_t>(entry->flags);
            parsedEntry.fieldFlags = static_cast<std::uint32_t>(entry->fieldFlags);
            parsedEntry.r0Status = static_cast<std::uint32_t>(entry->r0Status);
            parsedEntry.stackFieldSource = static_cast<std::uint32_t>(entry->stackFieldSource);
            parsedEntry.ioFieldSource = static_cast<std::uint32_t>(entry->ioFieldSource);
            parsedEntry.initialStack = static_cast<std::uint64_t>(entry->initialStack);
            parsedEntry.stackLimit = static_cast<std::uint64_t>(entry->stackLimit);
            parsedEntry.stackBase = static_cast<std::uint64_t>(entry->stackBase);
            parsedEntry.kernelStack = static_cast<std::uint64_t>(entry->kernelStack);
            parsedEntry.readOperationCount = static_cast<std::uint64_t>(entry->readOperationCount);
            parsedEntry.writeOperationCount = static_cast<std::uint64_t>(entry->writeOperationCount);
            parsedEntry.otherOperationCount = static_cast<std::uint64_t>(entry->otherOperationCount);
            parsedEntry.readTransferCount = static_cast<std::uint64_t>(entry->readTransferCount);
            parsedEntry.writeTransferCount = static_cast<std::uint64_t>(entry->writeTransferCount);
            parsedEntry.otherTransferCount = static_cast<std::uint64_t>(entry->otherTransferCount);
            parsedEntry.ktInitialStackOffset = static_cast<std::uint32_t>(entry->ktInitialStackOffset);
            parsedEntry.ktStackLimitOffset = static_cast<std::uint32_t>(entry->ktStackLimitOffset);
            parsedEntry.ktStackBaseOffset = static_cast<std::uint32_t>(entry->ktStackBaseOffset);
            parsedEntry.ktKernelStackOffset = static_cast<std::uint32_t>(entry->ktKernelStackOffset);
            parsedEntry.ktReadOperationCountOffset = static_cast<std::uint32_t>(entry->ktReadOperationCountOffset);
            parsedEntry.ktWriteOperationCountOffset = static_cast<std::uint32_t>(entry->ktWriteOperationCountOffset);
            parsedEntry.ktOtherOperationCountOffset = static_cast<std::uint32_t>(entry->ktOtherOperationCountOffset);
            parsedEntry.ktReadTransferCountOffset = static_cast<std::uint32_t>(entry->ktReadTransferCountOffset);
            parsedEntry.ktWriteTransferCountOffset = static_cast<std::uint32_t>(entry->ktWriteTransferCountOffset);
            parsedEntry.ktOtherTransferCountOffset = static_cast<std::uint32_t>(entry->ktOtherTransferCountOffset);
            parsedEntry.dynDataCapabilityMask = static_cast<std::uint64_t>(entry->dynDataCapabilityMask);
            enumResult.entries.push_back(parsedEntry);
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

    ProcessCrossViewResult DriverClient::queryProcessCrossView(
        const unsigned long flags,
        const std::uint32_t startPid,
        const std::uint32_t endPid,
        const unsigned long maxNodes,
        DriverHandle* const existingHandle) const
    {
        // Input: Process cross-view query flags, PID range, and maximum node budget.
        // Handling: Call R0 read-only cross-view IOCTL; decode the EPROCESS source matrix based on entrySize.
        // Return: ProcessCrossViewResult; unsupported=true indicates an outdated driver or missing IOCTL integration.
        ProcessCrossViewResult crossViewResult{};
        KSWORD_ARK_PROCESS_CROSSVIEW_REQUEST request{};
        request.version = KSWORD_ARK_CROSSVIEW_PROTOCOL_VERSION;
        request.flags = flags;
        request.startPid = startPid;
        request.endPid = endPid;
        request.maxNodes = maxNodes;

        std::vector<std::uint8_t> responseBuffer(4U * 1024U * 1024U, 0U);
        crossViewResult.io = deviceIoControl(
            IOCTL_KSWORD_ARK_QUERY_PROCESS_CROSSVIEW,
            &request,
            static_cast<unsigned long>(sizeof(request)),
            responseBuffer.data(),
            static_cast<unsigned long>(responseBuffer.size()),
            existingHandle);
        if (!crossViewResult.io.ok)
        {
            crossViewResult.unsupported = detail::isUnsupportedIoctlError(crossViewResult.io.win32Error);
            crossViewResult.io.message = crossViewResult.unsupported
                ? "IOCTL_KSWORD_ARK_QUERY_PROCESS_CROSSVIEW unsupported or driver version is too old"
                : "DeviceIoControl(IOCTL_KSWORD_ARK_QUERY_PROCESS_CROSSVIEW) failed, error=" +
                    std::to_string(crossViewResult.io.win32Error);
            return crossViewResult;
        }
        if (crossViewResult.io.bytesReturned < kProcessCrossViewHeaderSize)
        {
            crossViewResult.io.ok = false;
            crossViewResult.io.message =
                "process cross-view response too small, bytesReturned=" +
                std::to_string(crossViewResult.io.bytesReturned);
            return crossViewResult;
        }

        const auto* responseHeader =
            reinterpret_cast<const KSWORD_ARK_PROCESS_CROSSVIEW_RESPONSE*>(responseBuffer.data());
        if (responseHeader->entrySize < sizeof(KSWORD_ARK_PROCESS_CROSSVIEW_ROW))
        {
            crossViewResult.io.ok = false;
            crossViewResult.io.message =
                "process cross-view entrySize invalid, entrySize=" +
                std::to_string(responseHeader->entrySize);
            return crossViewResult;
        }

        crossViewResult.version = static_cast<std::uint32_t>(responseHeader->version);
        crossViewResult.status = static_cast<std::uint32_t>(responseHeader->status);
        crossViewResult.totalCount = static_cast<std::uint32_t>(responseHeader->totalCount);
        crossViewResult.returnedCount = static_cast<std::uint32_t>(responseHeader->returnedCount);
        crossViewResult.dynDataCapabilityMask = static_cast<std::uint64_t>(responseHeader->dynDataCapabilityMask);
        crossViewResult.missingCapabilityMask = static_cast<std::uint64_t>(responseHeader->missingCapabilityMask);
        crossViewResult.lastStatus = static_cast<long>(responseHeader->lastStatus);
        crossViewResult.fieldOffsets = copyCrossViewOffsets(responseHeader->fieldOffsets);
        crossViewResult.io.ntStatus = crossViewResult.lastStatus;
        if (static_cast<unsigned long>(crossViewResult.lastStatus) == 0xC00000BBUL ||
            static_cast<unsigned long>(crossViewResult.lastStatus) == 0xC0000010UL)
        {
            crossViewResult.unsupported = true;
            crossViewResult.io.ok = false;
            crossViewResult.io.message =
                "IOCTL_KSWORD_ARK_QUERY_PROCESS_CROSSVIEW unsupported by current driver response";
            return crossViewResult;
        }

        const std::size_t kAvailableCount =
            (static_cast<std::size_t>(crossViewResult.io.bytesReturned) - kProcessCrossViewHeaderSize) /
            static_cast<std::size_t>(responseHeader->entrySize);
        const std::size_t kParsedCount = std::min<std::size_t>(
            static_cast<std::size_t>(responseHeader->returnedCount),
            kAvailableCount);
        crossViewResult.entries.reserve(kParsedCount);
        for (std::size_t index = 0U; index < kParsedCount; ++index)
        {
            const std::size_t kEntryOffset =
                kProcessCrossViewHeaderSize +
                (index * static_cast<std::size_t>(responseHeader->entrySize));
            if (kEntryOffset + sizeof(KSWORD_ARK_PROCESS_CROSSVIEW_ROW) > responseBuffer.size())
            {
                break;
            }

            const auto* sourceRow =
                reinterpret_cast<const KSWORD_ARK_PROCESS_CROSSVIEW_ROW*>(responseBuffer.data() + kEntryOffset);
            ProcessCrossViewEntry row{};
            row.objectAddress = static_cast<std::uint64_t>(sourceRow->objectAddress);
            row.startAddress = static_cast<std::uint64_t>(sourceRow->startAddress);
            row.processId = static_cast<std::uint32_t>(sourceRow->processId);
            row.parentProcessId = static_cast<std::uint32_t>(sourceRow->parentProcessId);
            row.sourceMask = static_cast<std::uint32_t>(sourceRow->sourceMask);
            row.anomalyFlags = static_cast<std::uint32_t>(sourceRow->anomalyFlags);
            row.dynDataCapabilityMask = static_cast<std::uint64_t>(sourceRow->dynDataCapabilityMask);
            row.fieldOffsets = copyCrossViewOffsets(sourceRow->fieldOffsets);
            row.lastStatus = static_cast<long>(sourceRow->lastStatus);
            row.confidence = static_cast<std::uint32_t>(sourceRow->confidence);
            row.publicProcessId = static_cast<std::uint32_t>(sourceRow->publicProcessId);
            row.activeListProcessId = static_cast<std::uint32_t>(sourceRow->activeListProcessId);
            row.cidTableProcessId = static_cast<std::uint32_t>(sourceRow->cidTableProcessId);
            row.publicWalkStatus = static_cast<long>(sourceRow->publicWalkStatus);
            row.activeListStatus = static_cast<long>(sourceRow->activeListStatus);
            row.cidTableStatus = static_cast<long>(sourceRow->cidTableStatus);
            row.detailStatus = static_cast<std::uint32_t>(sourceRow->detailStatus);
            row.denoiseFlags = static_cast<std::uint32_t>(sourceRow->denoiseFlags);
            row.imageName = detail::readFixedString(sourceRow->imageName, sizeof(sourceRow->imageName));
            row.detail = detail::readFixedString(sourceRow->detail, sizeof(sourceRow->detail));
            crossViewResult.entries.push_back(std::move(row));
        }

        std::ostringstream stream;
        stream << "version=" << crossViewResult.version
            << ", status=" << crossViewResult.status
            << ", total=" << crossViewResult.totalCount
            << ", returned=" << crossViewResult.returnedCount
            << ", parsed=" << crossViewResult.entries.size()
            << ", missingCaps=0x" << std::hex << std::uppercase << crossViewResult.missingCapabilityMask
            << ", lastStatus=0x" << static_cast<unsigned long>(crossViewResult.lastStatus);
        crossViewResult.io.message = stream.str();
        return crossViewResult;
    }

    ThreadCrossViewResult DriverClient::queryThreadCrossView(
        const unsigned long flags,
        const std::uint32_t processId,
        const std::uint32_t startTid,
        const std::uint32_t endTid,
        const unsigned long maxNodes) const
    {
        // Input: thread cross-view query flags, optional PID/TID ranges, and node budget.
        // Processing: Invoke R0 read-only thread evidence IOCTL, decode ETHREAD/KTHREAD rows by entrySize.
        // Return: ThreadCrossViewResult, containing evidence for orphan/CID-only/start-address anomalies.
        ThreadCrossViewResult crossViewResult{};
        KSWORD_ARK_THREAD_CROSSVIEW_REQUEST request{};
        request.version = KSWORD_ARK_CROSSVIEW_PROTOCOL_VERSION;
        request.flags = flags;
        request.processId = processId;
        request.startTid = startTid;
        request.endTid = endTid;
        request.maxNodes = maxNodes;

        std::vector<std::uint8_t> responseBuffer(4U * 1024U * 1024U, 0U);
        crossViewResult.io = deviceIoControl(
            IOCTL_KSWORD_ARK_QUERY_THREAD_CROSSVIEW,
            &request,
            static_cast<unsigned long>(sizeof(request)),
            responseBuffer.data(),
            static_cast<unsigned long>(responseBuffer.size()));
        if (!crossViewResult.io.ok)
        {
            crossViewResult.unsupported = detail::isUnsupportedIoctlError(crossViewResult.io.win32Error);
            crossViewResult.io.message = crossViewResult.unsupported
                ? "IOCTL_KSWORD_ARK_QUERY_THREAD_CROSSVIEW unsupported or driver version is too old"
                : "DeviceIoControl(IOCTL_KSWORD_ARK_QUERY_THREAD_CROSSVIEW) failed, error=" +
                    std::to_string(crossViewResult.io.win32Error);
            return crossViewResult;
        }
        if (crossViewResult.io.bytesReturned < kThreadCrossViewHeaderSize)
        {
            crossViewResult.io.ok = false;
            crossViewResult.io.message =
                "thread cross-view response too small, bytesReturned=" +
                std::to_string(crossViewResult.io.bytesReturned);
            return crossViewResult;
        }

        const auto* responseHeader =
            reinterpret_cast<const KSWORD_ARK_THREAD_CROSSVIEW_RESPONSE*>(responseBuffer.data());
        if (responseHeader->entrySize < sizeof(KSWORD_ARK_THREAD_CROSSVIEW_ROW))
        {
            crossViewResult.io.ok = false;
            crossViewResult.io.message =
                "thread cross-view entrySize invalid, entrySize=" +
                std::to_string(responseHeader->entrySize);
            return crossViewResult;
        }

        crossViewResult.version = static_cast<std::uint32_t>(responseHeader->version);
        crossViewResult.status = static_cast<std::uint32_t>(responseHeader->status);
        crossViewResult.totalCount = static_cast<std::uint32_t>(responseHeader->totalCount);
        crossViewResult.returnedCount = static_cast<std::uint32_t>(responseHeader->returnedCount);
        crossViewResult.dynDataCapabilityMask = static_cast<std::uint64_t>(responseHeader->dynDataCapabilityMask);
        crossViewResult.missingCapabilityMask = static_cast<std::uint64_t>(responseHeader->missingCapabilityMask);
        crossViewResult.lastStatus = static_cast<long>(responseHeader->lastStatus);
        crossViewResult.fieldOffsets = copyCrossViewOffsets(responseHeader->fieldOffsets);
        crossViewResult.io.ntStatus = crossViewResult.lastStatus;
        if (static_cast<unsigned long>(crossViewResult.lastStatus) == 0xC00000BBUL ||
            static_cast<unsigned long>(crossViewResult.lastStatus) == 0xC0000010UL)
        {
            crossViewResult.unsupported = true;
            crossViewResult.io.ok = false;
            crossViewResult.io.message =
                "IOCTL_KSWORD_ARK_QUERY_THREAD_CROSSVIEW unsupported by current driver response";
            return crossViewResult;
        }

        const std::size_t kAvailableCount =
            (static_cast<std::size_t>(crossViewResult.io.bytesReturned) - kThreadCrossViewHeaderSize) /
            static_cast<std::size_t>(responseHeader->entrySize);
        const std::size_t kParsedCount = std::min<std::size_t>(
            static_cast<std::size_t>(responseHeader->returnedCount),
            kAvailableCount);
        crossViewResult.entries.reserve(kParsedCount);
        for (std::size_t index = 0U; index < kParsedCount; ++index)
        {
            const std::size_t kEntryOffset =
                kThreadCrossViewHeaderSize +
                (index * static_cast<std::size_t>(responseHeader->entrySize));
            if (kEntryOffset + sizeof(KSWORD_ARK_THREAD_CROSSVIEW_ROW) > responseBuffer.size())
            {
                break;
            }

            const auto* sourceRow =
                reinterpret_cast<const KSWORD_ARK_THREAD_CROSSVIEW_ROW*>(responseBuffer.data() + kEntryOffset);
            ThreadCrossViewEntry row{};
            row.objectAddress = static_cast<std::uint64_t>(sourceRow->objectAddress);
            row.processObjectAddress = static_cast<std::uint64_t>(sourceRow->processObjectAddress);
            row.startAddress = static_cast<std::uint64_t>(sourceRow->startAddress);
            row.processId = static_cast<std::uint32_t>(sourceRow->processId);
            row.threadId = static_cast<std::uint32_t>(sourceRow->threadId);
            row.sourceMask = static_cast<std::uint32_t>(sourceRow->sourceMask);
            row.anomalyFlags = static_cast<std::uint32_t>(sourceRow->anomalyFlags);
            row.dynDataCapabilityMask = static_cast<std::uint64_t>(sourceRow->dynDataCapabilityMask);
            row.fieldOffsets = copyCrossViewOffsets(sourceRow->fieldOffsets);
            row.lastStatus = static_cast<long>(sourceRow->lastStatus);
            row.confidence = static_cast<std::uint32_t>(sourceRow->confidence);
            row.publicThreadId = static_cast<std::uint32_t>(sourceRow->publicThreadId);
            row.threadListThreadId = static_cast<std::uint32_t>(sourceRow->threadListThreadId);
            row.cidTableThreadId = static_cast<std::uint32_t>(sourceRow->cidTableThreadId);
            row.publicProcessId = static_cast<std::uint32_t>(sourceRow->publicProcessId);
            row.threadListProcessId = static_cast<std::uint32_t>(sourceRow->threadListProcessId);
            row.cidTableProcessId = static_cast<std::uint32_t>(sourceRow->cidTableProcessId);
            row.publicWalkStatus = static_cast<long>(sourceRow->publicWalkStatus);
            row.threadListStatus = static_cast<long>(sourceRow->threadListStatus);
            row.cidTableStatus = static_cast<long>(sourceRow->cidTableStatus);
            row.startAddressStatus = static_cast<long>(sourceRow->startAddressStatus);
            row.detailStatus = static_cast<std::uint32_t>(sourceRow->detailStatus);
            row.denoiseFlags = static_cast<std::uint32_t>(sourceRow->denoiseFlags);
            row.imageName = detail::readFixedString(sourceRow->imageName, sizeof(sourceRow->imageName));
            row.detail = detail::readFixedString(sourceRow->detail, sizeof(sourceRow->detail));
            crossViewResult.entries.push_back(std::move(row));
        }

        std::ostringstream stream;
        stream << "version=" << crossViewResult.version
            << ", status=" << crossViewResult.status
            << ", total=" << crossViewResult.totalCount
            << ", returned=" << crossViewResult.returnedCount
            << ", parsed=" << crossViewResult.entries.size()
            << ", missingCaps=0x" << std::hex << std::uppercase << crossViewResult.missingCapabilityMask
            << ", lastStatus=0x" << static_cast<unsigned long>(crossViewResult.lastStatus);
        crossViewResult.io.message = stream.str();
        return crossViewResult;
    }

    namespace
    {
        bool isUnsupportedRuntimeDetailResponse(
            const unsigned long detailStatus,
            const long lastStatus)
        {
            // Input: semantic status and NTSTATUS from the fixed R0 detailed response.
            // Processing: Identify old driver/protocol versions or unimplemented paths; do not treat them as UI crashes or parsing failures.
            // Return: true indicates the caller should display unsupported/unavailable.
            return detailStatus == KSWORD_ARK_DETAIL_STATUS_UNSUPPORTED ||
                static_cast<unsigned long>(lastStatus) == 0xC00000BBUL ||
                static_cast<unsigned long>(lastStatus) == 0xC0000010UL;
        }

        std::string buildRuntimeDetailMessage(
            const char* const operationName,
            const unsigned long detailStatus,
            const unsigned long fieldFlags,
            const unsigned long long missingCapabilityMask,
            const long lastStatus,
            const unsigned long bytesReturned)
        {
            // Input: Core diagnostic fields of the fixed detail response.
            // Processing: Generate a stable summary line for display in the UI's last column or details area.
            // Returns: std::string containing status, field bits, missing capabilities, and byte count.
            std::ostringstream stream;
            stream << (operationName != nullptr ? operationName : "runtime detail")
                << " status=" << detailStatus
                << ", fields=0x" << std::hex << std::uppercase << fieldFlags
                << ", missingCaps=0x" << missingCapabilityMask
                << ", lastStatus=0x" << static_cast<unsigned long>(lastStatus)
                << std::dec << ", bytesReturned=" << bytesReturned;
            return stream.str();
        }
    }

    ProcessRuntimeDetailResult DriverClient::queryProcessRuntimeDetail(
        const std::uint32_t processId,
        const unsigned long flags,
        DriverHandle* const existingHandle) const
    {
        // Input: Target PID and field group flags.
        // Handling: Wrap IOCTL_KSWORD_ARK_QUERY_PROCESS_DETAIL; provide a clear error when the response is insufficient.
        // Returns: ProcessRuntimeDetailResult; unsupported=true indicates the old driver lacks the entry point or R0 explicitly did not implement it.
        constexpr const char* kOperationName = "IOCTL_KSWORD_ARK_QUERY_PROCESS_DETAIL";
        ProcessRuntimeDetailResult detailResult{};
        KSWORD_ARK_PROCESS_DETAIL_REQUEST request{};
        request.version = KSWORD_ARK_RUNTIME_DETAIL_PROTOCOL_VERSION;
        request.flags = flags;
        request.processId = processId;

        detailResult.io = deviceIoControl(
            IOCTL_KSWORD_ARK_QUERY_PROCESS_DETAIL,
            &request,
            static_cast<unsigned long>(sizeof(request)),
            &detailResult.response,
            static_cast<unsigned long>(sizeof(detailResult.response)),
            existingHandle);
        if (!detailResult.io.ok)
        {
            detailResult.unsupported = detail::isUnsupportedIoctlError(detailResult.io.win32Error);
            detailResult.io.message = detailResult.unsupported
                ? "IOCTL_KSWORD_ARK_QUERY_PROCESS_DETAIL unsupported or driver version is too old"
                : "DeviceIoControl(IOCTL_KSWORD_ARK_QUERY_PROCESS_DETAIL) failed, error=" +
                    std::to_string(detailResult.io.win32Error);
            return detailResult;
        }

        if (detailResult.io.bytesReturned < sizeof(detailResult.response))
        {
            detailResult.io.ok = false;
            detailResult.io.win32Error = ERROR_INSUFFICIENT_BUFFER;
            detailResult.io.message =
                "process runtime detail response too small, bytesReturned=" +
                std::to_string(detailResult.io.bytesReturned);
            return detailResult;
        }

        detailResult.io.ntStatus = detailResult.response.lastStatus;
        detailResult.unsupported = isUnsupportedRuntimeDetailResponse(
            detailResult.response.status,
            detailResult.response.lastStatus);
        detailResult.io.message = buildRuntimeDetailMessage(
            kOperationName,
            detailResult.response.status,
            detailResult.response.fieldFlags,
            detailResult.response.missingCapabilityMask,
            detailResult.response.lastStatus,
            detailResult.io.bytesReturned);
        return detailResult;
    }

    ThreadRuntimeDetailResult DriverClient::queryThreadRuntimeDetail(
        const std::uint32_t threadId,
        const std::uint32_t processId,
        const unsigned long flags) const
    {
        // Input: target TID, optional PID constraint, and field group flags.
        // Processing: Encapsulates IOCTL_KSWORD_ARK_QUERY_THREAD_DETAIL; PID mismatch is recorded in the R0 semantic status.
        // Return: ThreadRuntimeDetailResult; the caller displays evidence only and does not execute thread actions.
        constexpr const char* kOperationName = "IOCTL_KSWORD_ARK_QUERY_THREAD_DETAIL";
        ThreadRuntimeDetailResult detailResult{};
        KSWORD_ARK_THREAD_DETAIL_REQUEST request{};
        request.version = KSWORD_ARK_RUNTIME_DETAIL_PROTOCOL_VERSION;
        request.flags = flags;
        request.threadId = threadId;
        request.processId = processId;

        detailResult.io = deviceIoControl(
            IOCTL_KSWORD_ARK_QUERY_THREAD_DETAIL,
            &request,
            static_cast<unsigned long>(sizeof(request)),
            &detailResult.response,
            static_cast<unsigned long>(sizeof(detailResult.response)));
        if (!detailResult.io.ok)
        {
            detailResult.unsupported = detail::isUnsupportedIoctlError(detailResult.io.win32Error);
            detailResult.io.message = detailResult.unsupported
                ? "IOCTL_KSWORD_ARK_QUERY_THREAD_DETAIL unsupported or driver version is too old"
                : "DeviceIoControl(IOCTL_KSWORD_ARK_QUERY_THREAD_DETAIL) failed, error=" +
                    std::to_string(detailResult.io.win32Error);
            return detailResult;
        }

        if (detailResult.io.bytesReturned < sizeof(detailResult.response))
        {
            detailResult.io.ok = false;
            detailResult.io.win32Error = ERROR_INSUFFICIENT_BUFFER;
            detailResult.io.message =
                "thread runtime detail response too small, bytesReturned=" +
                std::to_string(detailResult.io.bytesReturned);
            return detailResult;
        }

        detailResult.io.ntStatus = detailResult.response.lastStatus;
        detailResult.unsupported = isUnsupportedRuntimeDetailResponse(
            detailResult.response.status,
            detailResult.response.lastStatus);
        detailResult.io.message = buildRuntimeDetailMessage(
            kOperationName,
            detailResult.response.status,
            detailResult.response.fieldFlags,
            detailResult.response.missingCapabilityMask,
            detailResult.response.lastStatus,
            detailResult.io.bytesReturned);
        return detailResult;
    }

    namespace
    {
        std::size_t runtimeFieldSampleResponseHeaderSize()
        {
            // Inputs: None.
            // Processing: Deduct the placeholder for entries[1] to obtain the variable-length response header length.
            // Returns the header size for parsing R0 runtime field sample responses.
            return sizeof(KSWORD_ARK_RUNTIME_FIELD_SAMPLE_RESPONSE) -
                sizeof(KSWORD_ARK_RUNTIME_FIELD_SAMPLE_ROW);
        }

        std::size_t processRuntimeFieldSampleRequestHeaderSize()
        {
            // Inputs: None.
            // Processing: Subtract the items[1] placeholder to get the process sample request header length.
            // Returns: The header size used to construct the IOCTL input buffer.
            return sizeof(KSWORD_ARK_PROCESS_RUNTIME_FIELD_SAMPLE_REQUEST) -
                sizeof(KSWORD_ARK_RUNTIME_FIELD_SAMPLE_ITEM_REQUEST);
        }

        std::size_t threadRuntimeFieldSampleRequestHeaderSize()
        {
            // Inputs: None.
            // Processing: Subtract the items[1] placeholder to get the thread sample request header length.
            // Returns: The header size used to construct the IOCTL input buffer.
            return sizeof(KSWORD_ARK_THREAD_RUNTIME_FIELD_SAMPLE_REQUEST) -
                sizeof(KSWORD_ARK_RUNTIME_FIELD_SAMPLE_ITEM_REQUEST);
        }

        std::string buildRuntimeFieldSampleMessage(
            const char* const operationName,
            const RuntimeFieldSampleResult& result,
            const unsigned long bytesReturned)
        {
            // Input: Sampler operation name, parsed response, and number of bytes returned by DeviceIoControl.
            // Handling: Generate a stable, UI-readable diagnostic line.
            // Returns: A std::string, used by the details page to convert to Chinese descriptions or for direct debugging.
            std::ostringstream stream;
            stream << (operationName != nullptr ? operationName : "runtime field sample")
                << " status=" << result.status
                << ", returned=" << result.returnedCount
                << "/" << result.totalCount
                << ", object=0x" << std::hex << std::uppercase << result.objectAddress
                << ", dynCaps=0x" << result.dynDataCapabilityMask
                << ", lastStatus=0x" << static_cast<unsigned long>(result.lastStatus)
                << std::dec << ", bytesReturned=" << bytesReturned;
            return stream.str();
        }

        RuntimeFieldSampleResult parseRuntimeFieldSampleResponse(
            IoResult ioResult,
            const std::vector<std::uint8_t>& responseBuffer,
            const std::vector<RuntimeFieldSampleRequestItem>& requestedItems,
            const char* const operationName)
        {
            // Input: DeviceIoControl result, raw response buffer, and request metadata.
            // Processing: Validate variable-length response header/entrySize and convert R0 rows to R3 models.
            // Return: RuntimeFieldSampleResult; on failure, io.ok=false and a clear message is retained.
            RuntimeFieldSampleResult result{};
            const std::size_t kHeaderSize = runtimeFieldSampleResponseHeaderSize();
            result.io = ioResult;

            if (!result.io.ok)
            {
                result.unsupported = detail::isUnsupportedIoctlError(result.io.win32Error);
                result.io.message = result.unsupported
                    ? std::string(operationName) + " unsupported or driver version is too old"
                    : std::string("DeviceIoControl(") + operationName + ") failed, error=" +
                        std::to_string(result.io.win32Error);
                return result;
            }
            if (result.io.bytesReturned < kHeaderSize || responseBuffer.size() < kHeaderSize)
            {
                result.io.ok = false;
                result.io.win32Error = ERROR_INSUFFICIENT_BUFFER;
                result.io.message = std::string(operationName) +
                    " response too small, bytesReturned=" +
                    std::to_string(result.io.bytesReturned);
                return result;
            }

            const auto* response = reinterpret_cast<const KSWORD_ARK_RUNTIME_FIELD_SAMPLE_RESPONSE*>(responseBuffer.data());
            result.version = static_cast<std::uint32_t>(response->version);
            result.status = static_cast<std::uint32_t>(response->status);
            result.totalCount = static_cast<std::uint32_t>(response->totalCount);
            result.returnedCount = static_cast<std::uint32_t>(response->returnedCount);
            result.entrySize = static_cast<std::uint32_t>(response->entrySize);
            result.flags = static_cast<std::uint32_t>(response->flags);
            result.lastStatus = response->lastStatus;
            result.objectAddress = static_cast<std::uint64_t>(response->objectAddress);
            result.dynDataCapabilityMask = static_cast<std::uint64_t>(response->dynDataCapabilityMask);
            result.io.ntStatus = response->lastStatus;

            if (result.entrySize < sizeof(KSWORD_ARK_RUNTIME_FIELD_SAMPLE_ROW))
            {
                result.io.ok = false;
                result.io.win32Error = ERROR_INVALID_DATA;
                result.io.message = std::string(operationName) + " invalid entrySize=" +
                    std::to_string(result.entrySize);
                return result;
            }

            const std::size_t kAvailableRows =
                (result.io.bytesReturned - kHeaderSize) / result.entrySize;
            const std::size_t kParsedRows = std::min<std::size_t>(
                kAvailableRows,
                static_cast<std::size_t>(result.returnedCount));
            result.entries.reserve(kParsedRows);
            for (std::size_t rowIndex = 0; rowIndex < kParsedRows; ++rowIndex)
            {
                const auto* row = reinterpret_cast<const KSWORD_ARK_RUNTIME_FIELD_SAMPLE_ROW*>(
                    responseBuffer.data() + kHeaderSize + (rowIndex * result.entrySize));
                RuntimeFieldSampleEntry entry{};
                entry.runtimeItemId = static_cast<std::uint32_t>(row->runtimeItemId);
                entry.offset = static_cast<std::uint32_t>(row->offset);
                entry.size = static_cast<std::uint32_t>(row->size);
                entry.status = static_cast<std::uint32_t>(row->status);
                entry.bytesRead = static_cast<std::uint32_t>(row->bytesRead);
                entry.flags = static_cast<std::uint32_t>(row->flags);
                entry.lastStatus = row->lastStatus;
                entry.valueU64 = static_cast<std::uint64_t>(row->valueU64);
                const std::size_t kByteCount = std::min<std::size_t>(
                    row->bytesRead,
                    KSWORD_ARK_RUNTIME_FIELD_SAMPLE_MAX_VALUE_BYTES);
                entry.sampleBytes.assign(row->sampleBytes, row->sampleBytes + kByteCount);
                if (rowIndex < requestedItems.size())
                {
                    entry.name = requestedItems[rowIndex].name;
                    entry.type = requestedItems[rowIndex].type;
                }
                result.entries.push_back(std::move(entry));
            }

            result.io.message = buildRuntimeFieldSampleMessage(
                operationName,
                result,
                result.io.bytesReturned);
            return result;
        }
    }

    RuntimeFieldSampleResult DriverClient::queryProcessRuntimeFieldSamples(
        const std::uint32_t processId,
        const std::vector<RuntimeFieldSampleRequestItem>& items,
        const unsigned long flags) const
    {
        // Input: Target PID and deep PDB field list.
        // Processing: Construct variable-length request, invoke read-only 0x83E sampler.
        // Return: RuntimeFieldSampleResult; unsupported=true if the old driver or protocol is missing.
        constexpr const char* kOperationName = "IOCTL_KSWORD_ARK_QUERY_PROCESS_RUNTIME_FIELDS";
        const std::size_t kItemCount = std::min<std::size_t>(items.size(), KSWORD_ARK_RUNTIME_FIELD_SAMPLE_MAX_ITEMS);
        const std::size_t kHeaderSize = processRuntimeFieldSampleRequestHeaderSize();
        const std::size_t kInputSize = kHeaderSize +
            (kItemCount * sizeof(KSWORD_ARK_RUNTIME_FIELD_SAMPLE_ITEM_REQUEST));
        const std::size_t kOutputSize = runtimeFieldSampleResponseHeaderSize() +
            (kItemCount * sizeof(KSWORD_ARK_RUNTIME_FIELD_SAMPLE_ROW));
        std::vector<std::uint8_t> inputBuffer(kInputSize, 0U);
        std::vector<std::uint8_t> outputBuffer(kOutputSize, 0U);
        auto* request = reinterpret_cast<KSWORD_ARK_PROCESS_RUNTIME_FIELD_SAMPLE_REQUEST*>(inputBuffer.data());
        request->version = KSWORD_ARK_RUNTIME_FIELD_SAMPLE_PROTOCOL_VERSION;
        request->flags = flags;
        request->processId = processId;
        request->itemCount = static_cast<unsigned long>(kItemCount);
        for (std::size_t itemIndex = 0; itemIndex < kItemCount; ++itemIndex)
        {
            request->items[itemIndex].runtimeItemId = items[itemIndex].runtimeItemId;
            request->items[itemIndex].offset = items[itemIndex].offset;
            request->items[itemIndex].size = items[itemIndex].size;
            request->items[itemIndex].flags = items[itemIndex].flags;
        }

        IoResult ioResult = deviceIoControl(
            IOCTL_KSWORD_ARK_QUERY_PROCESS_RUNTIME_FIELDS,
            inputBuffer.data(),
            static_cast<unsigned long>(inputBuffer.size()),
            outputBuffer.data(),
            static_cast<unsigned long>(outputBuffer.size()));
        return parseRuntimeFieldSampleResponse(
            ioResult,
            outputBuffer,
            items,
            kOperationName);
    }

    RuntimeFieldSampleResult DriverClient::queryThreadRuntimeFieldSamples(
        const std::uint32_t threadId,
        const std::uint32_t processId,
        const std::vector<RuntimeFieldSampleRequestItem>& items,
        const unsigned long flags) const
    {
        // Input: Target TID, optional PID, and deep PDB field list.
        // Processing: Construct variable-length request, invoke read-only 0x83F sampler.
        // Return: RuntimeFieldSampleResult; unsupported=true if the old driver or protocol is missing.
        constexpr const char* kOperationName = "IOCTL_KSWORD_ARK_QUERY_THREAD_RUNTIME_FIELDS";
        const std::size_t kItemCount = std::min<std::size_t>(items.size(), KSWORD_ARK_RUNTIME_FIELD_SAMPLE_MAX_ITEMS);
        const std::size_t kHeaderSize = threadRuntimeFieldSampleRequestHeaderSize();
        const std::size_t kInputSize = kHeaderSize +
            (kItemCount * sizeof(KSWORD_ARK_RUNTIME_FIELD_SAMPLE_ITEM_REQUEST));
        const std::size_t kOutputSize = runtimeFieldSampleResponseHeaderSize() +
            (kItemCount * sizeof(KSWORD_ARK_RUNTIME_FIELD_SAMPLE_ROW));
        std::vector<std::uint8_t> inputBuffer(kInputSize, 0U);
        std::vector<std::uint8_t> outputBuffer(kOutputSize, 0U);
        auto* request = reinterpret_cast<KSWORD_ARK_THREAD_RUNTIME_FIELD_SAMPLE_REQUEST*>(inputBuffer.data());
        request->version = KSWORD_ARK_RUNTIME_FIELD_SAMPLE_PROTOCOL_VERSION;
        request->flags = flags;
        request->threadId = threadId;
        request->processId = processId;
        request->itemCount = static_cast<unsigned long>(kItemCount);
        for (std::size_t itemIndex = 0; itemIndex < kItemCount; ++itemIndex)
        {
            request->items[itemIndex].runtimeItemId = items[itemIndex].runtimeItemId;
            request->items[itemIndex].offset = items[itemIndex].offset;
            request->items[itemIndex].size = items[itemIndex].size;
            request->items[itemIndex].flags = items[itemIndex].flags;
        }

        IoResult ioResult = deviceIoControl(
            IOCTL_KSWORD_ARK_QUERY_THREAD_RUNTIME_FIELDS,
            inputBuffer.data(),
            static_cast<unsigned long>(inputBuffer.size()),
            outputBuffer.data(),
            static_cast<unsigned long>(outputBuffer.size()));
        return parseRuntimeFieldSampleResponse(
            ioResult,
            outputBuffer,
            items,
            kOperationName);
    }

}

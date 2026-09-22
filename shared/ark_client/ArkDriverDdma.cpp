#include "ArkDriverClient.h"
// The interval predicate and R0 share the same pure function implementation; do not rewrite it in R3.
#include "../driver/KswordArkDdmaPlan.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

// ============================================================
// ArkDriverDdma.cpp
// Purpose:
// - Encapsulate VA → PA translation (reusing the existing R0 page table walk backend).
// - Encapsulate DDMA (Direct Disk Memory Access) capability querying and physical read/write operations.
//
// What is DDMA: Uses bus mastering DMA via the disk controller to read/write arbitrary physical addresses. The
// data path goes through the HBA rather than CPU page tables, so it is not constrained by SLAT/EPT and can see
// physical pages remapped by upper-layer virtualization. The cost is that a disk sector must be borrowed as a
// transit buffer, so every call must explicitly provide a temporary LBA; this file provides no default values.
// ============================================================

namespace ksword::ark
{
    namespace
    {
        // Header length is always taken as offsetof. The protocol side requires R0 to calculate the header length
        // using FIELD_OFFSET; R3 must use the exact same value, otherwise the overall parsing will be misaligned.
        constexpr std::size_t kDdmaQueryResponseHeaderSize =
            offsetof(KSWORD_ARK_DDMA_QUERY_CAPABILITY_RESPONSE, entries);
        constexpr std::size_t kDdmaReadResponseHeaderSize =
            offsetof(KSWORD_ARK_DDMA_READ_PHYSICAL_RESPONSE, data);
        constexpr std::size_t kDdmaWriteRequestHeaderSize =
            offsetof(KSWORD_ARK_DDMA_WRITE_PHYSICAL_REQUEST, data);

        // 48-bit LBA limit. Use the shared protocol constant; do not define a new literal here.
        constexpr std::uint64_t kDdmaLbaMax = KSWORD_ARK_DDMA_LBA48_LIMIT;

        // copyFixedWideString converts a fixed-length wchar_t array from the protocol into a std::wstring. If
        // no terminating NUL is present, it truncates to the array capacity to avoid out-of-bounds scanning.
        std::wstring copyFixedWideString(const wchar_t* const buffer, const std::size_t capacityChars)
        {
            if (buffer == nullptr || capacityChars == 0U)
            {
                return std::wstring();
            }
            std::size_t length = 0U;
            while (length < capacityChars && buffer[length] != L'\0')
            {
                ++length;
            }
            return std::wstring(buffer, length);
        }

        // Purpose of isDdmaUnsupported: Distinguish between "the driver does not recognize this IOCTL" and
        // "the driver recognizes it but rejected it." An unknown IOCTL returns STATUS_INVALID_DEVICE_REQUEST
        // at the dispatch layer, which maps to Win32's ERROR_INVALID_FUNCTION.
        bool isDdmaUnsupported(const IoResult& io)
        {
            return !io.ok &&
                (io.win32Error == static_cast<unsigned long>(ERROR_INVALID_FUNCTION) ||
                 io.win32Error == static_cast<unsigned long>(ERROR_NOT_SUPPORTED));
        }

        // isDdmaRangeAcceptable Purpose: Perform a pre-check using the exact same criteria as R0 before issuing
        // an IOCTL. The core criteria are shared pure functions defined in KswordArkDdmaPlan.h; duplicating
        // them on both sides is avoided. If the interval criteria diverge, R3 allowing while R0 rejects wastes
        // a round-trip, whereas R3 rejecting while R0 allows would let out-of-bounds requests reach the disk.
        bool isDdmaRangeAcceptable(const std::uint64_t physicalAddress, const std::uint32_t length)
        {
            return KswordArkDdmaIsPhysicalRangeValid(physicalAddress, length) != 0;
        }
    }

    VirtualAddressTranslateResult DriverClient::translateVirtualAddress(
        const std::uint32_t processId,
        const std::uint64_t virtualAddress,
        DriverHandle* const existingHandle) const
    {
        VirtualAddressTranslateResult translateResult{};
        KSWORD_ARK_TRANSLATE_VIRTUAL_ADDRESS_REQUEST request{};
        KSWORD_ARK_TRANSLATE_VIRTUAL_ADDRESS_RESPONSE response{};

        // The protocol requires flags/reserved to be zero; R0 treats any non-zero bits as invalid parameters.
        request.flags = 0UL;
        request.processId = processId;
        request.virtualAddress = virtualAddress;
        request.reserved = 0UL;

        translateResult.io = deviceIoControl(
            IOCTL_KSWORD_ARK_TRANSLATE_VIRTUAL_ADDRESS,
            &request,
            static_cast<unsigned long>(sizeof(request)),
            &response,
            static_cast<unsigned long>(sizeof(response)),
            existingHandle);
        if (!translateResult.io.ok)
        {
            translateResult.io.message =
                "DeviceIoControl(IOCTL_KSWORD_ARK_TRANSLATE_VIRTUAL_ADDRESS) failed, error=" +
                std::to_string(translateResult.io.win32Error);
            return translateResult;
        }
        if (translateResult.io.bytesReturned < sizeof(response))
        {
            translateResult.io.ok = false;
            translateResult.io.message =
                "translate-virtual-address response too small, bytesReturned=" +
                std::to_string(translateResult.io.bytesReturned);
            return translateResult;
        }

        const KSWORD_ARK_PAGE_TABLE_ENTRY_INFO& info = response.info;
        translateResult.version = static_cast<std::uint32_t>(info.version);
        translateResult.processId = static_cast<std::uint32_t>(info.processId);
        translateResult.fieldFlags = static_cast<std::uint32_t>(info.fieldFlags);
        translateResult.queryStatus = static_cast<std::uint32_t>(info.queryStatus);
        translateResult.lookupStatus = static_cast<long>(info.lookupStatus);
        translateResult.walkStatus = static_cast<long>(info.walkStatus);
        translateResult.virtualAddress = static_cast<std::uint64_t>(info.virtualAddress);
        translateResult.physicalAddress = static_cast<std::uint64_t>(info.physicalAddress);
        translateResult.cr3PhysicalAddress = static_cast<std::uint64_t>(info.cr3PhysicalAddress);
        translateResult.pageSize = static_cast<std::uint32_t>(info.pageSize);
        translateResult.largePageType = static_cast<std::uint32_t>(info.largePageType);
        translateResult.protection = static_cast<std::uint32_t>(info.protection);
        translateResult.confidence = static_cast<std::uint32_t>(info.confidence);

        // resolved must satisfy three conditions simultaneously: R0 reports successful resolution, the
        // aggregated status is OK, and fieldFlags actually contains the physical address bit. Relying solely
        // on the resolved field yields a meaningless physical address on the 'not-present entry' path.
        translateResult.resolved =
            (info.resolved != 0UL) &&
            (translateResult.queryStatus == KSWORD_ARK_MEMORY_TRANSLATE_STATUS_OK) &&
            ((translateResult.fieldFlags & KSWORD_ARK_MEMORY_FIELD_PHYSICAL_ADDRESS_PRESENT) != 0UL);

        return translateResult;
    }

    DdmaCapabilityResult DriverClient::queryDdmaCapability(
        const bool probeTransfer,
        const std::uint64_t scratchLba,
        const bool scratchLbaValid,
        const unsigned long maxDisks,
        DriverHandle* const existingHandle) const
    {
        DdmaCapabilityResult capabilityResult{};
        KSWORD_ARK_DDMA_QUERY_CAPABILITY_REQUEST request{};

        unsigned long requestedDisks = maxDisks;
        if (requestedDisks == 0UL)
        {
            requestedDisks = KSWORD_ARK_DDMA_DISK_LIMIT_DEFAULT;
        }
        if (requestedDisks > KSWORD_ARK_DDMA_DISK_LIMIT_HARD)
        {
            requestedDisks = KSWORD_ARK_DDMA_DISK_LIMIT_HARD;
        }

        if (scratchLbaValid && scratchLba >= kDdmaLbaMax)
        {
            capabilityResult.io.ok = false;
            capabilityResult.io.win32Error = ERROR_INVALID_PARAMETER;
            capabilityResult.io.message = "暂存 LBA 超出 48 位上限";
            return capabilityResult;
        }

        request.flags = 0UL;
        if (probeTransfer)
        {
            request.flags |= KSWORD_ARK_DDMA_QUERY_FLAG_PROBE_TRANSFER;
        }
        // The probe issues a read command to the specified LBA, so the caller must explicitly declare this LBA.
        // If not declared, the driver only enumerates devices without issuing commands; this is an intentionally retained fallback path.
        if (scratchLbaValid)
        {
            request.flags |= KSWORD_ARK_DDMA_FLAG_SCRATCH_LBA_VALID;
            request.scratchLba = scratchLba;
        }
        request.maxDisks = requestedDisks;

        std::vector<std::uint8_t> responseBuffer(
            kDdmaQueryResponseHeaderSize +
                (static_cast<std::size_t>(requestedDisks) * sizeof(KSWORD_ARK_DDMA_DISK_ENTRY)),
            0U);
        capabilityResult.io = deviceIoControl(
            IOCTL_KSWORD_ARK_DDMA_QUERY_CAPABILITY,
            &request,
            static_cast<unsigned long>(sizeof(request)),
            responseBuffer.data(),
            static_cast<unsigned long>(responseBuffer.size()),
            existingHandle);
        if (!capabilityResult.io.ok)
        {
            capabilityResult.unsupported = isDdmaUnsupported(capabilityResult.io);
            capabilityResult.io.message = capabilityResult.unsupported
                ? std::string("当前驱动不支持 DDMA（IOCTL_KSWORD_ARK_DDMA_QUERY_CAPABILITY 未注册）")
                : ("DeviceIoControl(IOCTL_KSWORD_ARK_DDMA_QUERY_CAPABILITY) failed, error=" +
                   std::to_string(capabilityResult.io.win32Error));
            return capabilityResult;
        }
        if (capabilityResult.io.bytesReturned < kDdmaQueryResponseHeaderSize)
        {
            capabilityResult.io.ok = false;
            capabilityResult.io.message =
                "ddma query response too small, bytesReturned=" +
                std::to_string(capabilityResult.io.bytesReturned);
            return capabilityResult;
        }

        const auto* responseHeader =
            reinterpret_cast<const KSWORD_ARK_DDMA_QUERY_CAPABILITY_RESPONSE*>(responseBuffer.data());
        capabilityResult.version = static_cast<std::uint32_t>(responseHeader->version);
        capabilityResult.status = static_cast<std::uint32_t>(responseHeader->status);
        capabilityResult.capabilityFlags = static_cast<std::uint32_t>(responseHeader->capabilityFlags);
        capabilityResult.totalDisks = static_cast<std::uint32_t>(responseHeader->totalDisks);
        capabilityResult.readyDisks = static_cast<std::uint32_t>(responseHeader->readyDisks);
        capabilityResult.transferBytes = static_cast<std::uint32_t>(responseHeader->transferBytes);
        capabilityResult.scratchSectorCount =
            static_cast<std::uint32_t>(responseHeader->scratchSectorCount);
        capabilityResult.lastStatus = static_cast<long>(responseHeader->lastStatus);
        capabilityResult.io.ntStatus = capabilityResult.lastStatus;

        // entrySize is self-reported by R0; the parse step size must follow it rather than the local sizeof,
        // so that adding fields to the protocol in the future does not cause the entire R3 row to misalign.
        const std::size_t kEntrySize = (responseHeader->entrySize != 0UL)
            ? static_cast<std::size_t>(responseHeader->entrySize)
            : sizeof(KSWORD_ARK_DDMA_DISK_ENTRY);
        if (kEntrySize < sizeof(KSWORD_ARK_DDMA_DISK_ENTRY))
        {
            capabilityResult.io.ok = false;
            capabilityResult.io.message =
                "ddma query entrySize smaller than known layout, entrySize=" +
                std::to_string(kEntrySize);
            return capabilityResult;
        }

        const std::size_t kAvailableCount =
            (static_cast<std::size_t>(capabilityResult.io.bytesReturned) - kDdmaQueryResponseHeaderSize) /
            kEntrySize;
        const std::size_t kParsedCount = std::min<std::size_t>(
            static_cast<std::size_t>(responseHeader->returnedDisks),
            kAvailableCount);

        capabilityResult.disks.reserve(kParsedCount);
        for (std::size_t index = 0U; index < kParsedCount; ++index)
        {
            const std::size_t kEntryOffset = kDdmaQueryResponseHeaderSize + (index * kEntrySize);
            const auto* entry = reinterpret_cast<const KSWORD_ARK_DDMA_DISK_ENTRY*>(
                responseBuffer.data() + kEntryOffset);

            DdmaDiskEntry diskEntry{};
            diskEntry.deviceIndex = static_cast<std::uint32_t>(entry->deviceIndex);
            diskEntry.diskFlags = static_cast<std::uint32_t>(entry->diskFlags);
            diskEntry.probeStatus = static_cast<long>(entry->probeStatus);
            diskEntry.scsiProbeStatus = static_cast<long>(entry->scsiProbeStatus);
            diskEntry.sectorSize = static_cast<std::uint32_t>(entry->sectorSize);
            if ((diskEntry.diskFlags & KSWORD_ARK_DDMA_DISK_FLAG_NAME_PRESENT) != 0UL)
            {
                diskEntry.deviceName =
                    copyFixedWideString(entry->deviceName, KSWORD_ARK_DDMA_DEVICE_NAME_CHARS);
            }
            capabilityResult.disks.push_back(diskEntry);
        }

        return capabilityResult;
    }

    DdmaReadResult DriverClient::ddmaReadPhysicalMemory(
        const std::uint32_t diskIndex,
        const std::uint64_t physicalAddress,
        const std::uint32_t bytesToRead,
        const std::uint64_t scratchLba,
        const unsigned long flags,
        DriverHandle* const existingHandle) const
    {
        DdmaReadResult readResult{};
        KSWORD_ARK_DDMA_READ_PHYSICAL_REQUEST request{};

        if ((flags & ~KSWORD_ARK_DDMA_READ_FLAG_ALLOWED) != 0UL)
        {
            readResult.io.ok = false;
            readResult.io.win32Error = ERROR_INVALID_PARAMETER;
            readResult.io.message = "DDMA 读取收到未知 flags 位";
            return readResult;
        }
        // Scratch LBA must be explicitly declared. This check blocks the request locally here to avoid a wasted IOCTL call.
        // The criterion is the flag bit, not whether scratchLba is zero, because LBA 0 is a valid value.
        if ((flags & KSWORD_ARK_DDMA_FLAG_SCRATCH_LBA_VALID) == 0UL)
        {
            readResult.io.ok = false;
            readResult.io.win32Error = ERROR_INVALID_PARAMETER;
            readResult.io.message = "DDMA 读取必须显式指定暂存扇区 LBA";
            return readResult;
        }
        if (scratchLba >= kDdmaLbaMax)
        {
            readResult.io.ok = false;
            readResult.io.win32Error = ERROR_INVALID_PARAMETER;
            readResult.io.message = "暂存 LBA 超出 48 位上限";
            return readResult;
        }
        if ((flags & KSWORD_ARK_DDMA_FLAG_SCRATCH_ACKNOWLEDGED) == 0UL)
        {
            readResult.io.ok = false;
            readResult.io.win32Error = ERROR_INVALID_PARAMETER;
            readResult.io.message = "DDMA 读取会临时覆盖暂存扇区，必须先确认";
            return readResult;
        }
        if (!isDdmaRangeAcceptable(physicalAddress, bytesToRead))
        {
            readResult.io.ok = false;
            readResult.io.win32Error = ERROR_INVALID_PARAMETER;
            readResult.io.message = "DDMA 读取区间无效：长度为 0、超过一页或跨页";
            return readResult;
        }

        request.flags = flags;
        request.diskIndex = diskIndex;
        request.physicalAddress = physicalAddress;
        request.scratchLba = scratchLba;
        request.bytesToRead = bytesToRead;
        request.reserved0 = 0UL;

        std::vector<std::uint8_t> responseBuffer(
            kDdmaReadResponseHeaderSize + static_cast<std::size_t>(bytesToRead),
            0U);
        readResult.io = deviceIoControl(
            IOCTL_KSWORD_ARK_DDMA_READ_PHYSICAL,
            &request,
            static_cast<unsigned long>(sizeof(request)),
            responseBuffer.data(),
            static_cast<unsigned long>(responseBuffer.size()),
            existingHandle);
        if (!readResult.io.ok)
        {
            readResult.unsupported = isDdmaUnsupported(readResult.io);
            readResult.io.message = readResult.unsupported
                ? std::string("当前驱动不支持 DDMA（IOCTL_KSWORD_ARK_DDMA_READ_PHYSICAL 未注册）")
                : ("DeviceIoControl(IOCTL_KSWORD_ARK_DDMA_READ_PHYSICAL) failed, error=" +
                   std::to_string(readResult.io.win32Error));
            return readResult;
        }
        if (readResult.io.bytesReturned < kDdmaReadResponseHeaderSize)
        {
            readResult.io.ok = false;
            readResult.io.message =
                "ddma read response too small, bytesReturned=" +
                std::to_string(readResult.io.bytesReturned);
            return readResult;
        }

        const auto* responseHeader =
            reinterpret_cast<const KSWORD_ARK_DDMA_READ_PHYSICAL_RESPONSE*>(responseBuffer.data());
        readResult.version = static_cast<std::uint32_t>(responseHeader->version);
        readResult.fieldFlags = static_cast<std::uint32_t>(responseHeader->fieldFlags);
        readResult.readStatus = static_cast<std::uint32_t>(responseHeader->readStatus);
        readResult.mapStatus = static_cast<long>(responseHeader->mapStatus);
        readResult.backupStatus = static_cast<long>(responseHeader->backupStatus);
        readResult.stageOutStatus = static_cast<long>(responseHeader->stageOutStatus);
        readResult.stageInStatus = static_cast<long>(responseHeader->stageInStatus);
        readResult.restoreStatus = static_cast<long>(responseHeader->restoreStatus);
        readResult.requestedPhysicalAddress =
            static_cast<std::uint64_t>(responseHeader->requestedPhysicalAddress);
        readResult.scratchLba = static_cast<std::uint64_t>(responseHeader->scratchLba);
        readResult.diskIndex = static_cast<std::uint32_t>(responseHeader->diskIndex);
        readResult.requestedBytes = static_cast<std::uint32_t>(responseHeader->requestedBytes);
        readResult.bytesRead = static_cast<std::uint32_t>(responseHeader->bytesRead);
        readResult.maxBytesPerRequest =
            static_cast<std::uint32_t>(responseHeader->maxBytesPerRequest);
        if ((readResult.fieldFlags & KSWORD_ARK_DDMA_FIELD_DEVICE_NAME_PRESENT) != 0UL)
        {
            readResult.deviceName =
                copyFixedWideString(responseHeader->deviceName, KSWORD_ARK_DDMA_DEVICE_NAME_CHARS);
        }

        // Payload length is determined by taking the minimum of bytesRead and buffer remaining capacity; it cannot be inferred from bytesReturned.
        const std::size_t kDataCapacity = responseBuffer.size() - kDdmaReadResponseHeaderSize;
        const std::size_t kDataBytes = std::min<std::size_t>(
            static_cast<std::size_t>(readResult.bytesRead),
            kDataCapacity);
        if (kDataBytes > 0U)
        {
            const std::uint8_t* const kDataStart =
                responseBuffer.data() + kDdmaReadResponseHeaderSize;
            readResult.data.assign(kDataStart, kDataStart + kDataBytes);
        }

        return readResult;
    }

    DdmaWriteResult DriverClient::ddmaWritePhysicalMemory(
        const std::uint32_t diskIndex,
        const std::uint64_t physicalAddress,
        const std::vector<std::uint8_t>& bytes,
        const std::uint64_t scratchLba,
        const unsigned long flags,
        DriverHandle* const existingHandle) const
    {
        DdmaWriteResult writeResult{};

        if ((flags & ~KSWORD_ARK_DDMA_WRITE_FLAG_ALLOWED) != 0UL)
        {
            writeResult.io.ok = false;
            writeResult.io.win32Error = ERROR_INVALID_PARAMETER;
            writeResult.io.message = "DDMA 写入收到未知 flags 位";
            return writeResult;
        }
        if ((flags & KSWORD_ARK_DDMA_FLAG_SCRATCH_LBA_VALID) == 0UL)
        {
            writeResult.io.ok = false;
            writeResult.io.win32Error = ERROR_INVALID_PARAMETER;
            writeResult.io.message = "DDMA 写入必须显式指定暂存扇区 LBA";
            return writeResult;
        }
        if (scratchLba >= kDdmaLbaMax)
        {
            writeResult.io.ok = false;
            writeResult.io.win32Error = ERROR_INVALID_PARAMETER;
            writeResult.io.message = "暂存 LBA 超出 48 位上限";
            return writeResult;
        }
        if ((flags & KSWORD_ARK_DDMA_FLAG_SCRATCH_ACKNOWLEDGED) == 0UL)
        {
            writeResult.io.ok = false;
            writeResult.io.win32Error = ERROR_INVALID_PARAMETER;
            writeResult.io.message = "DDMA 写入会临时覆盖暂存扇区，必须先确认";
            return writeResult;
        }
        if (bytes.empty() || bytes.size() > KSWORD_ARK_DDMA_WRITE_MAX_BYTES)
        {
            writeResult.io.ok = false;
            writeResult.io.win32Error = ERROR_INVALID_PARAMETER;
            writeResult.io.message = "DDMA 写入长度必须在 1 到一页之间";
            return writeResult;
        }
        if (!isDdmaRangeAcceptable(physicalAddress, static_cast<std::uint32_t>(bytes.size())))
        {
            writeResult.io.ok = false;
            writeResult.io.win32Error = ERROR_INVALID_PARAMETER;
            writeResult.io.message = "DDMA 写入区间无效：超过一页或跨页";
            return writeResult;
        }

        // Request header plus trailing payload; allocate based on the protocol header length.
        std::vector<std::uint8_t> requestBuffer(
            kDdmaWriteRequestHeaderSize + bytes.size(),
            0U);
        auto* request =
            reinterpret_cast<KSWORD_ARK_DDMA_WRITE_PHYSICAL_REQUEST*>(requestBuffer.data());
        request->flags = flags;
        request->diskIndex = diskIndex;
        request->physicalAddress = physicalAddress;
        request->scratchLba = scratchLba;
        request->bytesToWrite = static_cast<unsigned long>(bytes.size());
        request->reserved0 = 0UL;
        std::copy(bytes.begin(), bytes.end(), requestBuffer.data() + kDdmaWriteRequestHeaderSize);

        KSWORD_ARK_DDMA_WRITE_PHYSICAL_RESPONSE response{};
        writeResult.io = deviceIoControl(
            IOCTL_KSWORD_ARK_DDMA_WRITE_PHYSICAL,
            requestBuffer.data(),
            static_cast<unsigned long>(requestBuffer.size()),
            &response,
            static_cast<unsigned long>(sizeof(response)),
            existingHandle);
        if (!writeResult.io.ok)
        {
            writeResult.unsupported = isDdmaUnsupported(writeResult.io);
            writeResult.io.message = writeResult.unsupported
                ? std::string("当前驱动不支持 DDMA（IOCTL_KSWORD_ARK_DDMA_WRITE_PHYSICAL 未注册）")
                : ("DeviceIoControl(IOCTL_KSWORD_ARK_DDMA_WRITE_PHYSICAL) failed, error=" +
                   std::to_string(writeResult.io.win32Error));
            return writeResult;
        }
        if (writeResult.io.bytesReturned < sizeof(response))
        {
            writeResult.io.ok = false;
            writeResult.io.message =
                "ddma write response too small, bytesReturned=" +
                std::to_string(writeResult.io.bytesReturned);
            return writeResult;
        }

        writeResult.version = static_cast<std::uint32_t>(response.version);
        writeResult.fieldFlags = static_cast<std::uint32_t>(response.fieldFlags);
        writeResult.writeStatus = static_cast<std::uint32_t>(response.writeStatus);
        writeResult.mapStatus = static_cast<long>(response.mapStatus);
        writeResult.backupStatus = static_cast<long>(response.backupStatus);
        writeResult.stageOutStatus = static_cast<long>(response.stageOutStatus);
        writeResult.stageInStatus = static_cast<long>(response.stageInStatus);
        writeResult.restoreStatus = static_cast<long>(response.restoreStatus);
        writeResult.readbackStatus = static_cast<long>(response.readbackStatus);
        writeResult.requestedPhysicalAddress =
            static_cast<std::uint64_t>(response.requestedPhysicalAddress);
        writeResult.scratchLba = static_cast<std::uint64_t>(response.scratchLba);
        writeResult.diskIndex = static_cast<std::uint32_t>(response.diskIndex);
        writeResult.requestedBytes = static_cast<std::uint32_t>(response.requestedBytes);
        writeResult.bytesWritten = static_cast<std::uint32_t>(response.bytesWritten);
        writeResult.maxBytesPerRequest = static_cast<std::uint32_t>(response.maxBytesPerRequest);
        if ((writeResult.fieldFlags & KSWORD_ARK_DDMA_FIELD_DEVICE_NAME_PRESENT) != 0UL)
        {
            writeResult.deviceName =
                copyFixedWideString(response.deviceName, KSWORD_ARK_DDMA_DEVICE_NAME_CHARS);
        }

        return writeResult;
    }
}

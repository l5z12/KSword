#include "ArkDriverClient.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <sstream>
#include <vector>

namespace ksword::ark
{
    namespace
    {
        // kMappedFileNameChars usage: Limits the scan length of UTF-16 paths in the shared response.
        constexpr std::size_t kMappedFileNameChars =
            KSWORD_ARK_MEMORY_MAPPED_FILE_NAME_CHARS;

        constexpr std::size_t kReadResponseHeaderSize =
            offsetof(KSWORD_ARK_READ_VIRTUAL_MEMORY_RESPONSE, data);

        constexpr std::size_t kWriteRequestHeaderSize =
            offsetof(KSWORD_ARK_WRITE_VIRTUAL_MEMORY_REQUEST, data);

        // Physical read response: The driver calculates 'how much output buffer remains available' using sizeof - sizeof(data) =
        // 55, but writes the payload to ->data (offsetof = 48). Both numbers must be used and cannot substitute for each other.
        constexpr std::size_t kPhysicalReadResponseAllocSize =
            sizeof(KSWORD_ARK_READ_PHYSICAL_MEMORY_RESPONSE)
            - sizeof(((KSWORD_ARK_READ_PHYSICAL_MEMORY_RESPONSE*)nullptr)->data);   // 55
        constexpr std::size_t kPhysicalReadDataOffset =
            offsetof(KSWORD_ARK_READ_PHYSICAL_MEMORY_RESPONSE, data);               // 48
        constexpr std::size_t kPhysicalWriteRequestAllocSize =
            sizeof(KSWORD_ARK_WRITE_PHYSICAL_MEMORY_REQUEST)
            - sizeof(((KSWORD_ARK_WRITE_PHYSICAL_MEMORY_REQUEST*)nullptr)->data);   // 31

        // kPhysicalAddressMax usage: Consistent with the 52-bit limit in R0 memory_physical.c.
        constexpr std::uint64_t kPhysicalAddressMax = 0x000FFFFFFFFFFFFFULL;

        // isPhysicalRangeAcceptable purpose: Replicates the R0 range criteria. When length is 0, only the start address is validated;
        // otherwise, both the upper bound and wraparound are checked to avoid sending requests destined to be rejected to the driver.
        bool isPhysicalRangeAcceptable(
            const std::uint64_t physicalAddress,
            const std::uint64_t length)
        {
            if (physicalAddress > kPhysicalAddressMax)
            {
                return false;
            }
            if (length == 0ULL)
            {
                return true;
            }
            return length <= (kPhysicalAddressMax - physicalAddress + 1ULL);
        }
    }

    VirtualMemoryQueryResult DriverClient::queryVirtualMemory(
        const std::uint32_t processId,
        const std::uint64_t baseAddress,
        const unsigned long flags,
        DriverHandle* const existingHandle) const
    {
        // request/response: Carry a fixed-size R3/R0 virtual memory region query.
        VirtualMemoryQueryResult queryResult{};
        KSWORD_ARK_QUERY_VIRTUAL_MEMORY_REQUEST request{};
        KSWORD_ARK_QUERY_VIRTUAL_MEMORY_RESPONSE response{};
        request.flags = flags;
        request.processId = processId;
        request.baseAddress = baseAddress;

        // All device access continues through DriverClient; external callers do not interact with DeviceIoControl.
        queryResult.io = deviceIoControl(
            IOCTL_KSWORD_ARK_QUERY_VIRTUAL_MEMORY,
            &request,
            static_cast<unsigned long>(sizeof(request)),
            &response,
            static_cast<unsigned long>(sizeof(response)),
            existingHandle);
        if (!queryResult.io.ok)
        {
            queryResult.io.message =
                "DeviceIoControl(IOCTL_KSWORD_ARK_QUERY_VIRTUAL_MEMORY) failed, error=" +
                std::to_string(queryResult.io.win32Error);
            return queryResult;
        }

        // Reject parsing when the fixed response length is incomplete to avoid misinterpreting fields across different protocol versions.
        if (queryResult.io.bytesReturned < sizeof(response))
        {
            queryResult.io.ok = false;
            queryResult.io.message =
                "query-vm response too small, bytesReturned=" +
                std::to_string(queryResult.io.bytesReturned);
            return queryResult;
        }

        // Convert the following fields one by one to stable R3 types so that the plugin and main UI can share the same result model.
        queryResult.version = static_cast<std::uint32_t>(response.version);
        queryResult.processId = static_cast<std::uint32_t>(response.processId);
        queryResult.fieldFlags = static_cast<std::uint32_t>(response.fieldFlags);
        queryResult.queryStatus = static_cast<std::uint32_t>(response.queryStatus);
        queryResult.openStatus = static_cast<long>(response.openStatus);
        queryResult.basicStatus = static_cast<long>(response.basicStatus);
        queryResult.mappedFileNameStatus = static_cast<long>(response.mappedFileNameStatus);
        queryResult.source = static_cast<std::uint32_t>(response.source);
        queryResult.requestedBaseAddress =
            static_cast<std::uint64_t>(response.requestedBaseAddress);
        queryResult.baseAddress = static_cast<std::uint64_t>(response.baseAddress);
        queryResult.allocationBase = static_cast<std::uint64_t>(response.allocationBase);
        queryResult.regionSize = static_cast<std::uint64_t>(response.regionSize);
        queryResult.allocationProtect =
            static_cast<std::uint32_t>(response.allocationProtect);
        queryResult.state = static_cast<std::uint32_t>(response.state);
        queryResult.protect = static_cast<std::uint32_t>(response.protect);
        queryResult.type = static_cast<std::uint32_t>(response.type);

        // mappedFileNameLength: Searches for a NUL within a fixed array without relying on the driver writing a terminator.
        std::size_t mappedFileNameLength = 0U;
        while (mappedFileNameLength < kMappedFileNameChars &&
               response.mappedFileName[mappedFileNameLength] != L'\0')
        {
            ++mappedFileNameLength;
        }
        queryResult.mappedFileName.assign(
            response.mappedFileName,
            response.mappedFileName + mappedFileNameLength);

        // message usage: preserves key state for non-Qt callers to write directly to diagnostic logs.
        std::ostringstream stream;
        stream << "pid=" << queryResult.processId
            << ", requested=0x" << std::hex << std::uppercase
            << queryResult.requestedBaseAddress
            << ", base=0x" << queryResult.baseAddress
            << std::dec << ", size=" << queryResult.regionSize
            << ", status=" << queryResult.queryStatus
            << ", source=" << queryResult.source;
        queryResult.io.message = stream.str();
        return queryResult;
    }

    VirtualMemoryReadResult DriverClient::readVirtualMemory(
        const std::uint32_t processId,
        const std::uint64_t baseAddress,
        const std::uint32_t bytesToRead,
        const unsigned long flags,
        DriverHandle* const existingHandle) const
    {
        // request: Carries R3-to-R0 read parameters; the data buffer is parsed separately from the response.
        VirtualMemoryReadResult readResult{};
        KSWORD_ARK_READ_VIRTUAL_MEMORY_REQUEST request{};

        // bytesToRead performs upper-bound protection in R3 first to avoid constructing an oversized response buffer.
        if (bytesToRead > KSWORD_ARK_MEMORY_READ_MAX_BYTES)
        {
            readResult.io.ok = false;
            readResult.io.win32Error = ERROR_INVALID_PARAMETER;
            readResult.io.message = "readVirtualMemory size exceeds driver limit";
            return readResult;
        }

        // Fill request fields item by item to keep shared protocol field meanings clear.
        request.flags = flags;
        request.processId = processId;
        request.baseAddress = baseAddress;
        request.bytesToRead = bytesToRead;

        // responseBuffer contains a fixed header and data[], with a length equal to the request size plus the header.
        std::vector<std::uint8_t> responseBuffer(
            kReadResponseHeaderSize + static_cast<std::size_t>(bytesToRead),
            0U);
        readResult.io = deviceIoControl(
            IOCTL_KSWORD_ARK_READ_VIRTUAL_MEMORY,
            &request,
            static_cast<unsigned long>(sizeof(request)),
            responseBuffer.data(),
            static_cast<unsigned long>(responseBuffer.size()),
            existingHandle);
        if (!readResult.io.ok)
        {
            readResult.io.message =
                "DeviceIoControl(IOCTL_KSWORD_ARK_READ_VIRTUAL_MEMORY) failed, error=" +
                std::to_string(readResult.io.win32Error);
            return readResult;
        }

        // Insufficient fixed header indicates a driver or protocol mismatch; mark as failure immediately.
        if (readResult.io.bytesReturned < kReadResponseHeaderSize)
        {
            readResult.io.ok = false;
            readResult.io.message =
                "read-vm response too small, bytesReturned=" +
                std::to_string(readResult.io.bytesReturned);
            return readResult;
        }

        // responseHeader points to a METHOD_BUFFERED response header; read-only parsing.
        const auto* responseHeader =
            reinterpret_cast<const KSWORD_ARK_READ_VIRTUAL_MEMORY_RESPONSE*>(responseBuffer.data());
        readResult.version = static_cast<std::uint32_t>(responseHeader->version);
        readResult.headerSize = static_cast<std::uint32_t>(responseHeader->headerSize);
        readResult.processId = static_cast<std::uint32_t>(responseHeader->processId);
        readResult.fieldFlags = static_cast<std::uint32_t>(responseHeader->fieldFlags);
        readResult.readStatus = static_cast<std::uint32_t>(responseHeader->readStatus);
        readResult.lookupStatus = static_cast<long>(responseHeader->lookupStatus);
        readResult.copyStatus = static_cast<long>(responseHeader->copyStatus);
        readResult.source = static_cast<std::uint32_t>(responseHeader->source);
        readResult.requestedBaseAddress = static_cast<std::uint64_t>(responseHeader->requestedBaseAddress);
        readResult.requestedBytes = static_cast<std::uint32_t>(responseHeader->requestedBytes);
        readResult.bytesRead = static_cast<std::uint32_t>(responseHeader->bytesRead);
        readResult.maxBytesPerRequest = static_cast<std::uint32_t>(responseHeader->maxBytesPerRequest);

        // dataBytes is constrained by bytesReturned, bytesRead, and buffer length.
        const std::size_t kBytesAvailable =
            static_cast<std::size_t>(readResult.io.bytesReturned) - kReadResponseHeaderSize;
        const std::size_t kDataBytes = std::min<std::size_t>(
            kBytesAvailable,
            static_cast<std::size_t>(readResult.bytesRead));
        if (kDataBytes > 0U)
        {
            readResult.data.assign(
                responseBuffer.begin() + static_cast<std::ptrdiff_t>(kReadResponseHeaderSize),
                responseBuffer.begin() + static_cast<std::ptrdiff_t>(kReadResponseHeaderSize + kDataBytes));
        }

        // Aggregate key diagnostic fields into a message for direct display in the UI status bar.
        std::ostringstream stream;
        stream << "pid=" << readResult.processId
            << ", address=0x" << std::hex << std::uppercase << readResult.requestedBaseAddress
            << std::dec << ", requested=" << readResult.requestedBytes
            << ", read=" << readResult.bytesRead
            << ", status=" << readResult.readStatus
            << ", source=" << readResult.source
            << ", flags=0x" << std::hex << std::uppercase << flags
            << ", nt=0x" << static_cast<unsigned long>(readResult.copyStatus);
        readResult.io.message = stream.str();
        return readResult;
    }

    VirtualMemoryWriteResult DriverClient::writeVirtualMemory(
        const std::uint32_t processId,
        const std::uint64_t baseAddress,
        const std::vector<std::uint8_t>& bytes,
        const unsigned long flags,
        DriverHandle* const existingHandle) const
    {
        // Purpose of writeResult: carries the fixed R0 response and DeviceIoControl status.
        VirtualMemoryWriteResult writeResult{};

        // Empty differences should not be passed to the driver; the caller should skip directly.
        if (bytes.empty() || bytes.size() > KSWORD_ARK_MEMORY_WRITE_MAX_BYTES)
        {
            writeResult.io.ok = false;
            writeResult.io.win32Error = ERROR_INVALID_PARAMETER;
            writeResult.io.message = "writeVirtualMemory invalid diff size";
            return writeResult;
        }

        // inputBuffer is constructed with the shared protocol header + data[] to avoid the UI directly assembling the IOCTL.
        std::vector<std::uint8_t> inputBuffer(kWriteRequestHeaderSize + bytes.size(), 0U);
        auto* request =
            reinterpret_cast<KSWORD_ARK_WRITE_VIRTUAL_MEMORY_REQUEST*>(inputBuffer.data());
        request->flags = flags;
        request->processId = processId;
        request->baseAddress = baseAddress;
        request->bytesToWrite = static_cast<unsigned long>(bytes.size());
        std::copy(bytes.begin(), bytes.end(), request->data);

        // response is a fixed-size structure; all write details are filled by R0.
        KSWORD_ARK_WRITE_VIRTUAL_MEMORY_RESPONSE response{};
        writeResult.io = deviceIoControl(
            IOCTL_KSWORD_ARK_WRITE_VIRTUAL_MEMORY,
            inputBuffer.data(),
            static_cast<unsigned long>(inputBuffer.size()),
            &response,
            static_cast<unsigned long>(sizeof(response)),
            existingHandle);
        if (!writeResult.io.ok)
        {
            writeResult.io.message =
                "DeviceIoControl(IOCTL_KSWORD_ARK_WRITE_VIRTUAL_MEMORY) failed, error=" +
                std::to_string(writeResult.io.win32Error);
            return writeResult;
        }
        if (writeResult.io.bytesReturned < sizeof(response))
        {
            writeResult.io.ok = false;
            writeResult.io.message =
                "write-vm response too small, bytesReturned=" +
                std::to_string(writeResult.io.bytesReturned);
            return writeResult;
        }

        // Parse response fields to allow the UI to determine success, partial success, or failure.
        writeResult.version = static_cast<std::uint32_t>(response.version);
        writeResult.processId = static_cast<std::uint32_t>(response.processId);
        writeResult.fieldFlags = static_cast<std::uint32_t>(response.fieldFlags);
        writeResult.writeStatus = static_cast<std::uint32_t>(response.writeStatus);
        writeResult.lookupStatus = static_cast<long>(response.lookupStatus);
        writeResult.copyStatus = static_cast<long>(response.copyStatus);
        writeResult.source = static_cast<std::uint32_t>(response.source);
        writeResult.requestedBaseAddress = static_cast<std::uint64_t>(response.requestedBaseAddress);
        writeResult.requestedBytes = static_cast<std::uint32_t>(response.requestedBytes);
        writeResult.bytesWritten = static_cast<std::uint32_t>(response.bytesWritten);
        writeResult.maxBytesPerRequest = static_cast<std::uint32_t>(response.maxBytesPerRequest);

        // message summarizes the write results for this difference block.
        std::ostringstream stream;
        stream << "pid=" << writeResult.processId
            << ", address=0x" << std::hex << std::uppercase << writeResult.requestedBaseAddress
            << std::dec << ", requested=" << writeResult.requestedBytes
            << ", written=" << writeResult.bytesWritten
            << ", status=" << writeResult.writeStatus
            << ", source=" << writeResult.source
            << ", flags=0x" << std::hex << std::uppercase << flags
            << ", fields=0x" << std::hex << std::uppercase << writeResult.fieldFlags
            << ", nt=0x" << std::hex << static_cast<unsigned long>(writeResult.copyStatus);
        if (writeResult.writeStatus == KSWORD_ARK_MEMORY_WRITE_STATUS_FORCE_REQUIRED)
        {
            stream << ", force-required";
        }
        writeResult.io.message = stream.str();
        return writeResult;
    }

    PhysicalMemoryReadResult DriverClient::readPhysicalMemory(
        const std::uint64_t physicalAddress,
        const std::uint32_t bytesToRead,
        const unsigned long flags,
        DriverHandle* const existingHandle) const
    {
        // request usage: Carries physical read parameters; the physical protocol has no processId, only address and length.
        PhysicalMemoryReadResult readResult{};
        KSWORD_ARK_READ_PHYSICAL_MEMORY_REQUEST request{};

        // The driver accepts only flags == 0 for physical reads; any reserved bits are treated as invalid parameters.
        if (flags != 0UL)
        {
            readResult.io.ok = false;
            readResult.io.win32Error = ERROR_INVALID_PARAMETER;
            readResult.io.message = "物理内存读取不接受任何 flags，flags 必须为 0";
            return readResult;
        }

        // Intercept the length limit in R3 first to avoid constructing a response buffer exceeding driver limits.
        if (bytesToRead > KSWORD_ARK_MEMORY_PHYSICAL_READ_MAX_BYTES)
        {
            readResult.io.ok = false;
            readResult.io.win32Error = ERROR_INVALID_PARAMETER;
            readResult.io.message = "物理内存读取长度超出驱动单次上限 64KB";
            return readResult;
        }

        // The upper address limit and wraparound are re-verified in R3 using criteria identical to R0.
        if (!isPhysicalRangeAcceptable(physicalAddress, static_cast<std::uint64_t>(bytesToRead)))
        {
            readResult.io.ok = false;
            readResult.io.win32Error = ERROR_INVALID_PARAMETER;
            readResult.io.message = "物理地址超出 52 位上限或区间回绕";
            return readResult;
        }

        // Fill request fields item by item; reserved/reserved2 remain zero, as the driver validates each individually.
        request.flags = 0UL;
        request.physicalAddress = physicalAddress;
        request.bytesToRead = bytesToRead;

        // The output buffer must be allocated at least kPhysicalReadResponseAllocSize bytes based on the driver's available
        // space criteria; providing only kPhysicalReadDataOffset + N will cause the driver to return BUFFER_TOO_SMALL.
        std::vector<std::uint8_t> responseBuffer(
            kPhysicalReadResponseAllocSize + static_cast<std::size_t>(bytesToRead),
            0U);
        readResult.io = deviceIoControl(
            IOCTL_KSWORD_ARK_READ_PHYSICAL_MEMORY,
            &request,
            static_cast<unsigned long>(sizeof(request)),
            responseBuffer.data(),
            static_cast<unsigned long>(responseBuffer.size()),
            existingHandle);
        if (!readResult.io.ok)
        {
            readResult.io.message =
                "DeviceIoControl(IOCTL_KSWORD_ARK_READ_PHYSICAL_MEMORY) failed, error=" +
                std::to_string(readResult.io.win32Error);
            return readResult;
        }

        // The driver always fills the response header even on IRQL/range-denied paths; insufficient length indicates a protocol mismatch.
        if (readResult.io.bytesReturned < kPhysicalReadResponseAllocSize)
        {
            readResult.io.ok = false;
            readResult.io.message =
                "read-physical response too small, bytesReturned=" +
                std::to_string(readResult.io.bytesReturned);
            return readResult;
        }

        // responseHeader points to a METHOD_BUFFERED response header; read-only parsing.
        const auto* responseHeader =
            reinterpret_cast<const KSWORD_ARK_READ_PHYSICAL_MEMORY_RESPONSE*>(responseBuffer.data());
        readResult.version = static_cast<std::uint32_t>(responseHeader->version);
        readResult.headerSize = static_cast<std::uint32_t>(responseHeader->headerSize);
        readResult.fieldFlags = static_cast<std::uint32_t>(responseHeader->fieldFlags);
        readResult.readStatus = static_cast<std::uint32_t>(responseHeader->readStatus);
        readResult.copyStatus = static_cast<long>(responseHeader->copyStatus);
        readResult.source = static_cast<std::uint32_t>(responseHeader->source);
        readResult.requestedPhysicalAddress =
            static_cast<std::uint64_t>(responseHeader->requestedPhysicalAddress);
        readResult.requestedBytes = static_cast<std::uint32_t>(responseHeader->requestedBytes);
        readResult.bytesRead = static_cast<std::uint32_t>(responseHeader->bytesRead);
        readResult.maxBytesPerRequest = static_cast<std::uint32_t>(responseHeader->maxBytesPerRequest);

        // The load start must be the true offset of the data member; using headerSize or 55 shifts the whole thing by 7 bytes.
        // Length is the minimum of bytesRead and remaining buffer capacity; it cannot be inferred from bytesReturned.
        const std::size_t kDataCapacity = responseBuffer.size() - kPhysicalReadDataOffset;
        const std::size_t kDataBytes = std::min<std::size_t>(
            static_cast<std::size_t>(readResult.bytesRead),
            kDataCapacity);
        if (kDataBytes > 0U)
        {
            readResult.data.assign(
                responseBuffer.begin() + static_cast<std::ptrdiff_t>(kPhysicalReadDataOffset),
                responseBuffer.begin() + static_cast<std::ptrdiff_t>(kPhysicalReadDataOffset + kDataBytes));
        }

        // Aggregate key diagnostic fields into a message for direct display in the UI status bar.
        std::ostringstream stream;
        stream << "pa=0x" << std::hex << std::uppercase << readResult.requestedPhysicalAddress
            << std::dec << ", requested=" << readResult.requestedBytes
            << ", read=" << readResult.bytesRead
            << ", parsed=" << readResult.data.size()
            << ", status=" << readResult.readStatus
            << ", source=" << readResult.source
            << ", fields=0x" << std::hex << std::uppercase << readResult.fieldFlags
            << ", nt=0x" << static_cast<unsigned long>(readResult.copyStatus);
        readResult.io.message = stream.str();
        return readResult;
    }

    PhysicalMemoryWriteResult DriverClient::writePhysicalMemory(
        const std::uint64_t physicalAddress,
        const std::vector<std::uint8_t>& bytes,
        const unsigned long flags,
        DriverHandle* const existingHandle) const
    {
        // Purpose of writeResult: carries the fixed R0 response and DeviceIoControl status.
        PhysicalMemoryWriteResult writeResult{};

        // Empty payloads and oversized payloads are both rejected by the driver; filter them out here in advance.
        if (bytes.empty() || bytes.size() > KSWORD_ARK_MEMORY_PHYSICAL_WRITE_MAX_BYTES)
        {
            writeResult.io.ok = false;
            writeResult.io.win32Error = ERROR_INVALID_PARAMETER;
            writeResult.io.message = "物理内存写入长度必须非零且不超过 4KB";
            return writeResult;
        }

        // flags: Only combinations of UI_CONFIRMED and FORCE are allowed; the driver treats any other bits as invalid parameters.
        constexpr unsigned long kAllowedWriteFlags =
            KSWORD_ARK_PHYSICAL_WRITE_FLAG_UI_CONFIRMED | KSWORD_ARK_PHYSICAL_WRITE_FLAG_FORCE;
        if ((flags & ~kAllowedWriteFlags) != 0UL)
        {
            writeResult.io.ok = false;
            writeResult.io.win32Error = ERROR_INVALID_PARAMETER;
            writeResult.io.message = "物理内存写入 flags 只接受 UI_CONFIRMED 与 FORCE 的组合";
            return writeResult;
        }

        // The upper address limit and wraparound are re-verified in R3 using criteria identical to R0.
        if (!isPhysicalRangeAcceptable(physicalAddress, static_cast<std::uint64_t>(bytes.size())))
        {
            writeResult.io.ok = false;
            writeResult.io.win32Error = ERROR_INVALID_PARAMETER;
            writeResult.io.message = "物理地址超出 52 位上限或区间回绕";
            return writeResult;
        }

        // inputBuffer is constructed with the physical write request header followed by data[], with the payload copied via the
        // request->data member; offsets are not manually calculated to avoid desynchronization with the actual structure layout.
        std::vector<std::uint8_t> inputBuffer(kPhysicalWriteRequestAllocSize + bytes.size(), 0U);
        auto* request =
            reinterpret_cast<KSWORD_ARK_WRITE_PHYSICAL_MEMORY_REQUEST*>(inputBuffer.data());
        request->flags = flags;
        request->physicalAddress = physicalAddress;
        request->bytesToWrite = static_cast<unsigned long>(bytes.size());
        std::copy(bytes.begin(), bytes.end(), request->data);

        // response is a fixed-size structure; the states of the mapping and copy phases are filled by R0 separately.
        KSWORD_ARK_WRITE_PHYSICAL_MEMORY_RESPONSE response{};
        writeResult.io = deviceIoControl(
            IOCTL_KSWORD_ARK_WRITE_PHYSICAL_MEMORY,
            inputBuffer.data(),
            static_cast<unsigned long>(inputBuffer.size()),
            &response,
            static_cast<unsigned long>(sizeof(response)),
            existingHandle);
        if (!writeResult.io.ok)
        {
            writeResult.io.message =
                "DeviceIoControl(IOCTL_KSWORD_ARK_WRITE_PHYSICAL_MEMORY) failed, error=" +
                std::to_string(writeResult.io.win32Error);
            return writeResult;
        }
        if (writeResult.io.bytesReturned < sizeof(response))
        {
            writeResult.io.ok = false;
            writeResult.io.message =
                "write-physical response too small, bytesReturned=" +
                std::to_string(writeResult.io.bytesReturned);
            return writeResult;
        }

        // Parse response fields to allow the UI to determine success, the need for FORCE, or failure.
        writeResult.version = static_cast<std::uint32_t>(response.version);
        writeResult.fieldFlags = static_cast<std::uint32_t>(response.fieldFlags);
        writeResult.writeStatus = static_cast<std::uint32_t>(response.writeStatus);
        writeResult.mapStatus = static_cast<long>(response.mapStatus);
        writeResult.copyStatus = static_cast<long>(response.copyStatus);
        writeResult.source = static_cast<std::uint32_t>(response.source);
        writeResult.requestedPhysicalAddress =
            static_cast<std::uint64_t>(response.requestedPhysicalAddress);
        writeResult.requestedBytes = static_cast<std::uint32_t>(response.requestedBytes);
        writeResult.bytesWritten = static_cast<std::uint32_t>(response.bytesWritten);
        writeResult.maxBytesPerRequest = static_cast<std::uint32_t>(response.maxBytesPerRequest);

        // message summarizes the current physical write result, retaining both NTSTATUS values from map/copy.
        std::ostringstream stream;
        stream << "pa=0x" << std::hex << std::uppercase << writeResult.requestedPhysicalAddress
            << std::dec << ", requested=" << writeResult.requestedBytes
            << ", written=" << writeResult.bytesWritten
            << ", status=" << writeResult.writeStatus
            << ", source=" << writeResult.source
            << ", flags=0x" << std::hex << std::uppercase << flags
            << ", fields=0x" << std::hex << std::uppercase << writeResult.fieldFlags
            << ", map=0x" << std::hex << static_cast<unsigned long>(writeResult.mapStatus)
            << ", nt=0x" << std::hex << static_cast<unsigned long>(writeResult.copyStatus);
        // Without FORCE, io.ok may still be true even if the driver wrote zero bytes; writeStatus must be used to distinguish this case.
        if (writeResult.writeStatus == KSWORD_ARK_MEMORY_PHYSICAL_WRITE_STATUS_FORCE_REQUIRED)
        {
            stream << ", force-required";
        }
        writeResult.io.message = stream.str();
        return writeResult;
    }

    KernelMemoryEvidenceResult DriverClient::queryKernelMemoryEvidence(
        const unsigned long flags,
        const unsigned long maxRows,
        const std::uint64_t startAddress,
        const std::uint64_t endAddress,
        const std::uint64_t maxBytes,
        const unsigned long maxBigPoolRows,
        const unsigned long sampleBytes) const
    {
        // Input: read-only kernel memory evidence collection parameters, including source flags, address range, and budget.
        // Processing: Construct a fixed request, invoke the R0 evidence IOCTL, and parse the variable-length rows[] based on rowSize.
        // Return: KernelMemoryEvidenceResult; unsupported=true if the old driver is used or the IOCTL is not registered.
        KernelMemoryEvidenceResult evidenceResult{};
        KSWORD_ARK_SCAN_KERNEL_MEMORY_EVIDENCE_REQUEST request{};
        request.flags = flags;
        request.maxRows = maxRows;
        request.startAddress = startAddress;
        request.endAddress = endAddress;
        request.maxBytes = maxBytes;
        request.maxBigPoolRows = maxBigPoolRows;
        request.sampleBytes = sampleBytes;

        constexpr std::size_t kHeaderSize =
            sizeof(KSWORD_ARK_SCAN_KERNEL_MEMORY_EVIDENCE_RESPONSE) -
            sizeof(KSWORD_ARK_KERNEL_MEMORY_EVIDENCE_ROW);
        std::vector<std::uint8_t> responseBuffer(4U * 1024U * 1024U, 0U);
        evidenceResult.io = deviceIoControl(
            IOCTL_KSWORD_ARK_SCAN_KERNEL_MEMORY_EVIDENCE,
            &request,
            static_cast<unsigned long>(sizeof(request)),
            responseBuffer.data(),
            static_cast<unsigned long>(responseBuffer.size()));
        if (!evidenceResult.io.ok)
        {
            evidenceResult.unsupported =
                evidenceResult.io.win32Error == ERROR_INVALID_FUNCTION ||
                evidenceResult.io.win32Error == ERROR_NOT_SUPPORTED ||
                evidenceResult.io.win32Error == ERROR_INVALID_PARAMETER;
            evidenceResult.io.message = evidenceResult.unsupported
                ? "IOCTL_KSWORD_ARK_SCAN_KERNEL_MEMORY_EVIDENCE unsupported or driver version is too old"
                : "DeviceIoControl(IOCTL_KSWORD_ARK_SCAN_KERNEL_MEMORY_EVIDENCE) failed, error=" +
                    std::to_string(evidenceResult.io.win32Error);
            return evidenceResult;
        }
        if (evidenceResult.io.bytesReturned < kHeaderSize)
        {
            evidenceResult.io.ok = false;
            evidenceResult.io.message =
                "kernel memory evidence response too small, bytesReturned=" +
                std::to_string(evidenceResult.io.bytesReturned);
            return evidenceResult;
        }

        const auto* responseHeader =
            reinterpret_cast<const KSWORD_ARK_SCAN_KERNEL_MEMORY_EVIDENCE_RESPONSE*>(responseBuffer.data());
        if (responseHeader->rowSize < sizeof(KSWORD_ARK_KERNEL_MEMORY_EVIDENCE_ROW))
        {
            evidenceResult.io.ok = false;
            evidenceResult.io.message =
                "kernel memory evidence rowSize invalid, rowSize=" +
                std::to_string(responseHeader->rowSize);
            return evidenceResult;
        }

        evidenceResult.version = static_cast<std::uint32_t>(responseHeader->version);
        evidenceResult.status = static_cast<std::uint32_t>(responseHeader->status);
        evidenceResult.responseFlags = static_cast<std::uint32_t>(responseHeader->responseFlags);
        evidenceResult.sourceFlags = static_cast<std::uint32_t>(responseHeader->sourceFlags);
        evidenceResult.totalRows = static_cast<std::uint32_t>(responseHeader->totalRows);
        evidenceResult.returnedRows = static_cast<std::uint32_t>(responseHeader->returnedRows);
        evidenceResult.maxRows = static_cast<std::uint32_t>(responseHeader->maxRows);
        evidenceResult.maxBytes = static_cast<std::uint64_t>(responseHeader->maxBytes);
        evidenceResult.bytesScanned = static_cast<std::uint64_t>(responseHeader->bytesScanned);
        evidenceResult.moduleCount = static_cast<std::uint32_t>(responseHeader->moduleCount);
        evidenceResult.bigPoolRowsSeen = static_cast<std::uint32_t>(responseHeader->bigPoolRowsSeen);
        evidenceResult.lastStatus = static_cast<long>(responseHeader->lastStatus);
        evidenceResult.io.ntStatus = evidenceResult.lastStatus;
        if (static_cast<unsigned long>(evidenceResult.lastStatus) == 0xC00000BBUL ||
            static_cast<unsigned long>(evidenceResult.lastStatus) == 0xC0000010UL)
        {
            evidenceResult.unsupported = true;
            evidenceResult.io.ok = false;
            evidenceResult.io.message =
                "IOCTL_KSWORD_ARK_SCAN_KERNEL_MEMORY_EVIDENCE unsupported by current driver response";
            return evidenceResult;
        }

        const std::size_t kAvailableCount =
            (static_cast<std::size_t>(evidenceResult.io.bytesReturned) - kHeaderSize) /
            static_cast<std::size_t>(responseHeader->rowSize);
        const std::size_t kParsedCount = std::min<std::size_t>(
            static_cast<std::size_t>(responseHeader->returnedRows),
            kAvailableCount);
        evidenceResult.entries.reserve(kParsedCount);
        for (std::size_t index = 0U; index < kParsedCount; ++index)
        {
            const std::size_t kEntryOffset =
                kHeaderSize + (index * static_cast<std::size_t>(responseHeader->rowSize));
            if (kEntryOffset + sizeof(KSWORD_ARK_KERNEL_MEMORY_EVIDENCE_ROW) > responseBuffer.size())
            {
                break;
            }

            const auto* sourceRow =
                reinterpret_cast<const KSWORD_ARK_KERNEL_MEMORY_EVIDENCE_ROW*>(
                    responseBuffer.data() + kEntryOffset);
            KernelMemoryEvidenceEntry row{};
            row.evidenceKind = static_cast<std::uint32_t>(sourceRow->evidenceKind);
            row.pageSize = static_cast<std::uint32_t>(sourceRow->pageSize);
            row.permissionFlags = static_cast<std::uint32_t>(sourceRow->permissionFlags);
            row.ownerKind = static_cast<std::uint32_t>(sourceRow->ownerKind);
            row.riskFlags = static_cast<std::uint32_t>(sourceRow->riskFlags);
            row.moduleSize = static_cast<std::uint32_t>(sourceRow->moduleSize);
            row.confidence = static_cast<std::uint32_t>(sourceRow->confidence);
            row.bigPoolTag = static_cast<std::uint32_t>(sourceRow->bigPoolTag);
            row.bigPoolFlags = static_cast<std::uint32_t>(sourceRow->bigPoolFlags);
            row.sectionRva = static_cast<std::uint32_t>(sourceRow->sectionRva);
            row.sectionSize = static_cast<std::uint32_t>(sourceRow->sectionSize);
            row.hashAlgorithm = static_cast<std::uint32_t>(sourceRow->hashAlgorithm);
            row.sampleSize = static_cast<std::uint32_t>(sourceRow->sampleSize);
            row.lastStatus = static_cast<long>(sourceRow->lastStatus);
            row.virtualAddress = static_cast<std::uint64_t>(sourceRow->virtualAddress);
            row.regionSize = static_cast<std::uint64_t>(sourceRow->regionSize);
            row.moduleBase = static_cast<std::uint64_t>(sourceRow->moduleBase);
            row.ownerAddress = static_cast<std::uint64_t>(sourceRow->ownerAddress);
            row.contentHash = static_cast<std::uint64_t>(sourceRow->contentHash);

            const std::size_t kSectionNameLength = std::find(
                sourceRow->sectionName,
                sourceRow->sectionName + KSWORD_ARK_MEMORY_EVIDENCE_SECTION_NAME_BYTES,
                '\0') - sourceRow->sectionName;
            row.sectionName.assign(
                reinterpret_cast<const char*>(sourceRow->sectionName),
                reinterpret_cast<const char*>(sourceRow->sectionName + kSectionNameLength));

            const std::size_t kBoundedSampleBytes = std::min<std::size_t>(
                static_cast<std::size_t>(sourceRow->sampleSize),
                KSWORD_ARK_MEMORY_EVIDENCE_SECTION_SAMPLE_BYTES);
            row.sample.assign(sourceRow->sample, sourceRow->sample + kBoundedSampleBytes);

            std::size_t ownerChars = 0U;
            while (ownerChars < KSWORD_ARK_MEMORY_EVIDENCE_OWNER_NAME_CHARS &&
                sourceRow->ownerName[ownerChars] != L'\0')
            {
                ++ownerChars;
            }
            row.ownerName.assign(sourceRow->ownerName, sourceRow->ownerName + ownerChars);

            std::size_t detailChars = 0U;
            while (detailChars < KSWORD_ARK_MEMORY_EVIDENCE_DETAIL_CHARS &&
                sourceRow->detail[detailChars] != L'\0')
            {
                ++detailChars;
            }
            row.detail.assign(sourceRow->detail, sourceRow->detail + detailChars);
            evidenceResult.entries.push_back(std::move(row));
        }

        std::ostringstream stream;
        stream << "version=" << evidenceResult.version
            << ", status=" << evidenceResult.status
            << ", total=" << evidenceResult.totalRows
            << ", returned=" << evidenceResult.returnedRows
            << ", parsed=" << evidenceResult.entries.size()
            << ", bytesScanned=" << evidenceResult.bytesScanned
            << ", flags=0x" << std::hex << std::uppercase << evidenceResult.responseFlags
            << ", lastStatus=0x" << static_cast<unsigned long>(evidenceResult.lastStatus);
        evidenceResult.io.message = stream.str();
        return evidenceResult;
    }
}

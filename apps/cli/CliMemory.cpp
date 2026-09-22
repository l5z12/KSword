#include "CliSupport.h"

namespace ksword::cli
{
    // printPageTableInfo renders translate/query-pte shared response data.
    // Inputs: page table info and bytesReturned.
    // Processing: prints every relevant resolved address and raw entry value.
    // Returns: no value.
    void printPageTableInfo(const KSWORD_ARK_PAGE_TABLE_ENTRY_INFO& info, DWORD bytesReturned)
    {
        printResponseBanner(info.version, info.queryStatus, info.walkStatus, bytesReturned);
        std::wcout << L"pid=" << info.processId
                   << L" fields=0x" << std::hex << info.fieldFlags
                   << L" lookup=0x" << static_cast<unsigned long>(info.lookupStatus)
                   << L" va=" << hex64(info.virtualAddress)
                   << L" pa=" << hex64(info.physicalAddress)
                   << L" cr3=" << hex64(info.cr3PhysicalAddress)
                   << std::dec << L" resolved=" << info.resolved
                   << L" pageSize=" << info.pageSize
                   << L" largePageType=" << info.largePageType << L"\n";
        std::wcout << L"indexes pml4=" << info.pml4Index
                   << L" pdpt=" << info.pdptIndex
                   << L" pd=" << info.pdIndex
                   << L" pt=" << info.ptIndex << L"\n";
        std::wcout << L"entries pml4e=" << hex64(info.pml4eValue)
                   << L" pdpte=" << hex64(info.pdpteValue)
                   << L" pde=" << hex64(info.pdeValue)
                   << L" pte=" << hex64(info.pteValue) << L"\n";
    }

    // commandMemoryFamily implements all registered memory IOCTLs.
    // Inputs: argc/argv from wmain.
    // Processing: supports scalar args and explicit --hex/--data-file writes.
    // Returns: process exit code.
    int commandMemoryFamily(int argc, wchar_t* argv[])
    {
        if (argc < 3) { std::wcerr << L"error: memory requires a subcommand\n"; return 1; }
        const std::wstring kSub = argv[2];
        const NamedArgs kArgs = parseNamedArgs(argc, argv, 3);
        const bool kDump = getOptionBool(kArgs, L"--hexdump");
        IoctlResult io{};

        if (kSub == L"query-va")
        {
            KSWORD_ARK_QUERY_VIRTUAL_MEMORY_REQUEST request{};
            KSWORD_ARK_QUERY_VIRTUAL_MEMORY_RESPONSE response{};
            request.flags = getOptionU32(kArgs, L"--flags", KSWORD_ARK_MEMORY_QUERY_FLAG_INCLUDE_ALL);
            request.processId = requireOptionU32(kArgs, L"--pid");
            request.baseAddress = requireOptionU64(kArgs, L"--address");
            if (!sendFixedRequestResponse(IOCTL_KSWORD_ARK_QUERY_VIRTUAL_MEMORY, L"IOCTL_KSWORD_ARK_QUERY_VIRTUAL_MEMORY", request, response, io)) return 3;
            printResponseBanner(response.version, response.queryStatus, response.basicStatus, io.bytesReturned);
            std::wcout << L"pid=" << response.processId << L" fields=0x" << std::hex << response.fieldFlags
                       << L" requested=" << hex64(response.requestedBaseAddress)
                       << L" base=" << hex64(response.baseAddress)
                       << L" allocationBase=" << hex64(response.allocationBase)
                       << std::dec << L" regionSize=" << response.regionSize
                       << L" protect=0x" << std::hex << response.protect
                       << L" state=0x" << response.state << L" type=0x" << response.type << std::dec << L"\n";
            dumpWideText(L"mappedFile", fixedWide(response.mappedFileName, KSWORD_ARK_MEMORY_MAPPED_FILE_NAME_CHARS));
            return 0;
        }
        if (kSub == L"read-va")
        {
            KSWORD_ARK_READ_VIRTUAL_MEMORY_REQUEST request{};
            request.flags = getOptionU32(kArgs, L"--flags", 0U);
            request.processId = ((request.flags & KSWORD_ARK_MEMORY_READ_FLAG_KERNEL_ADDRESS) != 0UL)
                ? getOptionU32(kArgs, L"--pid", 0U)
                : requireOptionU32(kArgs, L"--pid");
            request.baseAddress = requireOptionU64(kArgs, L"--address");
            request.bytesToRead = requireOptionU32(kArgs, L"--bytes");
            if (request.bytesToRead > KSWORD_ARK_MEMORY_READ_MAX_BYTES) { std::wcerr << L"error: --bytes exceeds protocol max\n"; return 1; }
            constexpr std::size_t kHeaderSize = offsetof(KSWORD_ARK_READ_VIRTUAL_MEMORY_RESPONSE, data);
            std::vector<std::uint8_t> buffer(kHeaderSize + request.bytesToRead, 0U);
            const int kRc = sendRawIoctl(L"IOCTL_KSWORD_ARK_READ_VIRTUAL_MEMORY", IOCTL_KSWORD_ARK_READ_VIRTUAL_MEMORY, &request, sizeof(request), buffer, io);
            if (kRc != 0) return kRc;
            if (io.bytesReturned < kHeaderSize) { std::wcerr << L"error: read-va response too small\n"; return 4; }
            const auto* response = reinterpret_cast<const KSWORD_ARK_READ_VIRTUAL_MEMORY_RESPONSE*>(buffer.data());
            printResponseBanner(response->version, response->readStatus, response->copyStatus, io.bytesReturned);
            std::wcout << L"pid=" << response->processId << L" fields=0x" << std::hex << response->fieldFlags
                       << L" requestFlags=0x" << request.flags
                       << L" copyStatus=0x" << static_cast<unsigned long>(response->copyStatus)
                       << L" source=" << std::dec << response->source
                       << L" requested=" << response->requestedBytes << L" read=" << response->bytesRead
                       << L" max=" << response->maxBytesPerRequest
                       << L" address=" << hex64(response->requestedBaseAddress) << L"\n";
            const std::size_t kDataBytes = std::min<std::size_t>(static_cast<std::size_t>(io.bytesReturned) - kHeaderSize, response->bytesRead);
            if (kDump) hexdump(buffer.data() + kHeaderSize, kDataBytes);
            return 0;
        }
        if (kSub == L"write-va")
        {
            const std::vector<std::uint8_t> kBytes = loadBytesFromHexOrFile(kArgs, L"--hex", L"--data-file", KSWORD_ARK_MEMORY_WRITE_MAX_BYTES, true);
            if (kBytes.empty()) { std::wcerr << L"error: write-va payload is empty\n"; return 1; }
            constexpr std::size_t kHeaderSize = offsetof(KSWORD_ARK_WRITE_VIRTUAL_MEMORY_REQUEST, data);
            std::vector<std::uint8_t> input(kHeaderSize + kBytes.size(), 0U);
            auto* request = reinterpret_cast<KSWORD_ARK_WRITE_VIRTUAL_MEMORY_REQUEST*>(input.data());
            request->flags = getOptionU32(kArgs, L"--flags", KSWORD_ARK_MEMORY_WRITE_FLAG_UI_CONFIRMED);
            request->processId = ((request->flags & KSWORD_ARK_MEMORY_WRITE_FLAG_KERNEL_ADDRESS) != 0UL)
                ? getOptionU32(kArgs, L"--pid", 0U)
                : requireOptionU32(kArgs, L"--pid");
            request->baseAddress = requireOptionU64(kArgs, L"--address");
            request->bytesToWrite = static_cast<unsigned long>(kBytes.size());
            std::copy(kBytes.begin(), kBytes.end(), request->data);
            KSWORD_ARK_WRITE_VIRTUAL_MEMORY_RESPONSE response{};
            DriverHandle handle = openDriverOrReport();
            if (!handle.isValid()) return 2;
            io = sendIoctl(handle, IOCTL_KSWORD_ARK_WRITE_VIRTUAL_MEMORY, input.data(), checkedDwordSize(input.size()), &response, sizeof(response));
            if (!io.ok) { printWin32Error(L"IOCTL_KSWORD_ARK_WRITE_VIRTUAL_MEMORY", io.win32Error); return 3; }
            if (io.bytesReturned < sizeof(response)) { std::wcerr << L"error: write-va response too small\n"; return 4; }
            printResponseBanner(response.version, response.writeStatus, response.copyStatus, io.bytesReturned);
            std::wcout << L"pid=" << response.processId << L" fields=0x" << std::hex << response.fieldFlags
                       << L" requestFlags=0x" << request->flags
                       << L" copyStatus=0x" << static_cast<unsigned long>(response.copyStatus)
                       << L" source=" << std::dec << response.source
                       << L" address=" << hex64(response.requestedBaseAddress)
                       << L" requested=" << response.requestedBytes
                       << L" written=" << response.bytesWritten << L" max=" << response.maxBytesPerRequest << L"\n";
            return 0;
        }
        if (kSub == L"read-phys")
        {
            KSWORD_ARK_READ_PHYSICAL_MEMORY_REQUEST request{};
            request.physicalAddress = requireOptionU64(kArgs, L"--address");
            request.bytesToRead = requireOptionU32(kArgs, L"--bytes");
            if (request.bytesToRead > KSWORD_ARK_MEMORY_PHYSICAL_READ_MAX_BYTES) { std::wcerr << L"error: --bytes exceeds protocol max\n"; return 1; }
            // The physical read response contains two numerically inequivalent values that cannot substitute for each other:
            // headerSize = sizeof - sizeof(data) = 55; the driver uses this to determine 'how much output buffer remains available'
            //   and reports BytesWritten as 55 + bytesCopied, so allocation and lower-bound length checks must use this value.
            // dataOffset = offsetof(data) = 48, which is the actual location where the driver writes the payload via MmCopyMemory.
            constexpr std::size_t kHeaderSize = sizeof(KSWORD_ARK_READ_PHYSICAL_MEMORY_RESPONSE) - sizeof(((KSWORD_ARK_READ_PHYSICAL_MEMORY_RESPONSE*)nullptr)->data);
            constexpr std::size_t kDataOffset = offsetof(KSWORD_ARK_READ_PHYSICAL_MEMORY_RESPONSE, data);
            std::vector<std::uint8_t> buffer(kHeaderSize + request.bytesToRead, 0U);
            const int kRc = sendRawIoctl(L"IOCTL_KSWORD_ARK_READ_PHYSICAL_MEMORY", IOCTL_KSWORD_ARK_READ_PHYSICAL_MEMORY, &request, sizeof(request), buffer, io);
            if (kRc != 0) return kRc;
            if (io.bytesReturned < kHeaderSize) { std::wcerr << L"error: read-phys response too small\n"; return 4; }
            const auto* response = reinterpret_cast<const KSWORD_ARK_READ_PHYSICAL_MEMORY_RESPONSE*>(buffer.data());
            printResponseBanner(response->version, response->readStatus, response->copyStatus, io.bytesReturned);
            std::wcout << L"fields=0x" << std::hex << response->fieldFlags
                       << L" address=" << hex64(response->requestedPhysicalAddress)
                       << std::dec << L" requested=" << response->requestedBytes
                       << L" read=" << response->bytesRead << L" max=" << response->maxBytesPerRequest << L"\n";
            // The payload start must be the actual offset of data; using headerSize would shift the entire offset by 7 bytes.
            // Length is the minimum of bytesRead and remaining buffer space; it cannot be inferred from bytesReturned based on the '55' convention.
            const std::size_t kDataBytes = std::min<std::size_t>(response->bytesRead, buffer.size() - kDataOffset);
            if (kDump) hexdump(buffer.data() + kDataOffset, kDataBytes);
            return 0;
        }
        if (kSub == L"write-phys")
        {
            const std::vector<std::uint8_t> kBytes = loadBytesFromHexOrFile(kArgs, L"--hex", L"--data-file", KSWORD_ARK_MEMORY_PHYSICAL_WRITE_MAX_BYTES, true);
            if (kBytes.empty()) { std::wcerr << L"error: write-phys payload is empty\n"; return 1; }
            constexpr std::size_t kHeaderSize = sizeof(KSWORD_ARK_WRITE_PHYSICAL_MEMORY_REQUEST) - sizeof(((KSWORD_ARK_WRITE_PHYSICAL_MEMORY_REQUEST*)nullptr)->data);
            std::vector<std::uint8_t> input(kHeaderSize + kBytes.size(), 0U);
            auto* request = reinterpret_cast<KSWORD_ARK_WRITE_PHYSICAL_MEMORY_REQUEST*>(input.data());
            request->flags = getOptionU32(kArgs, L"--flags", KSWORD_ARK_PHYSICAL_WRITE_FLAG_UI_CONFIRMED);
            request->physicalAddress = requireOptionU64(kArgs, L"--address");
            request->bytesToWrite = static_cast<unsigned long>(kBytes.size());
            std::copy(kBytes.begin(), kBytes.end(), request->data);
            KSWORD_ARK_WRITE_PHYSICAL_MEMORY_RESPONSE response{};
            DriverHandle handle = openDriverOrReport();
            if (!handle.isValid()) return 2;
            io = sendIoctl(handle, IOCTL_KSWORD_ARK_WRITE_PHYSICAL_MEMORY, input.data(), checkedDwordSize(input.size()), &response, sizeof(response));
            if (!io.ok) { printWin32Error(L"IOCTL_KSWORD_ARK_WRITE_PHYSICAL_MEMORY", io.win32Error); return 3; }
            if (io.bytesReturned < sizeof(response)) { std::wcerr << L"error: write-phys response too small\n"; return 4; }
            printResponseBanner(response.version, response.writeStatus, response.copyStatus, io.bytesReturned);
            std::wcout << L"fields=0x" << std::hex << response.fieldFlags
                       << L" address=" << hex64(response.requestedPhysicalAddress)
                       << std::dec << L" requested=" << response.requestedBytes
                       << L" written=" << response.bytesWritten << L" max=" << response.maxBytesPerRequest << L"\n";
            return 0;
        }
        if (kSub == L"translate-va" || kSub == L"query-pte")
        {
            KSWORD_ARK_QUERY_PAGE_TABLE_ENTRY_REQUEST request{};
            request.flags = getOptionU32(kArgs, L"--flags", 0U);
            request.processId = requireOptionU32(kArgs, L"--pid");
            request.virtualAddress = requireOptionU64(kArgs, L"--address");
            if (kSub == L"translate-va")
            {
                KSWORD_ARK_TRANSLATE_VIRTUAL_ADDRESS_RESPONSE response{};
                if (!sendFixedRequestResponse(IOCTL_KSWORD_ARK_TRANSLATE_VIRTUAL_ADDRESS, L"IOCTL_KSWORD_ARK_TRANSLATE_VIRTUAL_ADDRESS", request, response, io)) return 3;
                printPageTableInfo(response.info, io.bytesReturned);
            }
            else
            {
                KSWORD_ARK_QUERY_PAGE_TABLE_ENTRY_RESPONSE response{};
                if (!sendFixedRequestResponse(IOCTL_KSWORD_ARK_QUERY_PAGE_TABLE_ENTRY, L"IOCTL_KSWORD_ARK_QUERY_PAGE_TABLE_ENTRY", request, response, io))
                {
                    return normalizeIoctlRc(L"memory pte", io, 3);
                }
                printPageTableInfo(response.info, io.bytesReturned);
            }
            return 0;
        }

        if (kSub == L"scan-kexec")
        {
            KSWORD_ARK_SCAN_KERNEL_EXECUTABLE_MEMORY_REQUEST request{};
            request.flags = getOptionU32(kArgs, L"--flags", KSWORD_ARK_KERNEL_EXEC_SCAN_FLAG_INCLUDE_ALL);
            request.maxEntries = getOptionU32(kArgs, L"--max-entries", 4096U);
            request.startAddress = getOptionU64(kArgs, L"--start", 0ULL);
            request.endAddress = getOptionU64(kArgs, L"--end", 0ULL);
            const std::uint32_t kLimit = getOptionU32(kArgs, L"--limit", 128U);
            std::vector<std::uint8_t> buffer(kHugeResponseBytes, 0U);
            const int kRc = sendRawIoctl(L"IOCTL_KSWORD_ARK_SCAN_KERNEL_EXECUTABLE_MEMORY", IOCTL_KSWORD_ARK_SCAN_KERNEL_EXECUTABLE_MEMORY, &request, sizeof(request), buffer, io);
            if (kRc != 0) return normalizeIoctlRc(L"memory kernel-exec", io, kRc);
            constexpr std::size_t kHeaderSize = sizeof(KSWORD_ARK_SCAN_KERNEL_EXECUTABLE_MEMORY_RESPONSE) - sizeof(KSWORD_ARK_KERNEL_EXECUTABLE_MEMORY_ENTRY);
            if (io.bytesReturned < kHeaderSize) { std::wcerr << L"error: scan-kexec response too small\n"; return 4; }
            const auto* response = reinterpret_cast<const KSWORD_ARK_SCAN_KERNEL_EXECUTABLE_MEMORY_RESPONSE*>(buffer.data());
            std::size_t available = 0U;
            try { available = validateVariable(io.bytesReturned, kHeaderSize, response->entrySize, sizeof(KSWORD_ARK_KERNEL_EXECUTABLE_MEMORY_ENTRY), L"scan-kexec"); }
            catch (...) { return 4; }
            printResponseBanner(response->version, response->status, response->lastStatus, io.bytesReturned);
            printCountHeader(response->version, response->totalCount, response->returnedCount, response->entrySize, io.bytesReturned);
            std::wcout << L"moduleCount=" << response->moduleCount << L"\n";
            const std::size_t kParsed = responseCountLimit(response->returnedCount, available, kLimit);
            for (std::size_t i = 0; i < kParsed; ++i)
            {
                const auto* entry = reinterpret_cast<const KSWORD_ARK_KERNEL_EXECUTABLE_MEMORY_ENTRY*>(buffer.data() + kHeaderSize + (i * response->entrySize));
                std::wcout << L"  [" << i << L"] va=" << hex64(entry->virtualAddress)
                           << L" pages=" << entry->pageCount << L" pageSize=" << entry->pageSize
                           << L" flags=0x" << std::hex << entry->effectiveFlags
                           << L" risk=0x" << entry->riskFlags
                           << L" moduleBase=" << hex64(entry->moduleBase)
                           << std::dec << L" owner=" << entry->ownerKind
                           << L" path='" << fixedWide(entry->modulePath, KSWORD_ARK_KERNEL_EXEC_MODULE_PATH_CHARS) << L"'\n";
            }
            return 0;
        }
        if (kSub == L"scan-evidence")
        {
            KSWORD_ARK_SCAN_KERNEL_MEMORY_EVIDENCE_REQUEST request{};
            request.flags = getOptionU32(kArgs, L"--flags", 0U);
            request.maxRows = getOptionU32(kArgs, L"--max-rows", KSWORD_ARK_MEMORY_EVIDENCE_DEFAULT_MAX_ROWS);
            request.startAddress = getOptionU64(kArgs, L"--start", 0ULL);
            request.endAddress = getOptionU64(kArgs, L"--end", 0ULL);
            request.maxBytes = getOptionU64(kArgs, L"--max-bytes", KSWORD_ARK_MEMORY_EVIDENCE_DEFAULT_MAX_BYTES);
            request.maxBigPoolRows = getOptionU32(kArgs, L"--max-bigpool-rows", KSWORD_ARK_MEMORY_EVIDENCE_DEFAULT_BIGPOOL_ROWS);
            request.sampleBytes = getOptionU32(kArgs, L"--sample-bytes", KSWORD_ARK_MEMORY_EVIDENCE_DEFAULT_SAMPLE_BYTES);
            const std::uint32_t kLimit = getOptionU32(kArgs, L"--limit", 128U);
            std::vector<std::uint8_t> buffer(kHugeResponseBytes, 0U);
            const int kRc = sendRawIoctl(L"IOCTL_KSWORD_ARK_SCAN_KERNEL_MEMORY_EVIDENCE", IOCTL_KSWORD_ARK_SCAN_KERNEL_MEMORY_EVIDENCE, &request, sizeof(request), buffer, io);
            if (kRc != 0) return normalizeIoctlRc(L"memory evidence", io, kRc);
            constexpr std::size_t kHeaderSize = sizeof(KSWORD_ARK_SCAN_KERNEL_MEMORY_EVIDENCE_RESPONSE) - sizeof(KSWORD_ARK_KERNEL_MEMORY_EVIDENCE_ROW);
            if (io.bytesReturned < kHeaderSize) { std::wcerr << L"error: scan-evidence response too small\n"; return 4; }
            const auto* response = reinterpret_cast<const KSWORD_ARK_SCAN_KERNEL_MEMORY_EVIDENCE_RESPONSE*>(buffer.data());
            std::size_t available = 0U;
            try { available = validateVariable(io.bytesReturned, kHeaderSize, response->rowSize, sizeof(KSWORD_ARK_KERNEL_MEMORY_EVIDENCE_ROW), L"scan-evidence"); }
            catch (...) { return 4; }
            printResponseBanner(response->version, response->status, response->lastStatus, io.bytesReturned);
            printCountHeader(response->version, response->totalRows, response->returnedRows, response->rowSize, io.bytesReturned);
            std::wcout << L"responseFlags=0x" << std::hex << response->responseFlags
                       << L" sourceFlags=0x" << response->sourceFlags
                       << std::dec << L" bytesScanned=" << response->bytesScanned
                       << L" modules=" << response->moduleCount << L" bigPoolSeen=" << response->bigPoolRowsSeen << L"\n";
            const std::size_t kParsed = responseCountLimit(response->returnedRows, available, kLimit);
            for (std::size_t i = 0; i < kParsed; ++i)
            {
                const auto* row = reinterpret_cast<const KSWORD_ARK_KERNEL_MEMORY_EVIDENCE_ROW*>(buffer.data() + kHeaderSize + (i * response->rowSize));
                std::wcout << L"  [" << i << L"] kind=" << row->evidenceKind
                           << L" va=" << hex64(row->virtualAddress)
                           << L" size=" << row->regionSize
                           << L" pageSize=" << row->pageSize
                           << L" perm=0x" << std::hex << row->permissionFlags
                           << L" risk=0x" << row->riskFlags
                           << L" moduleBase=" << hex64(row->moduleBase)
                           << L" ownerAddress=" << hex64(row->ownerAddress)
                           << L" last=0x" << static_cast<unsigned long>(row->lastStatus)
                           << std::dec << L" owner='" << fixedWide(row->ownerName, KSWORD_ARK_MEMORY_EVIDENCE_OWNER_NAME_CHARS)
                           << L"' detail='" << fixedWide(row->detail, KSWORD_ARK_MEMORY_EVIDENCE_DETAIL_CHARS) << L"'\n";
            }
            return 0;
        }
        if (kSub == L"enum-vad")
        {
            // R0 region view for injection trace checks. This is a **different source** than query-va:
            // The latter uses ZwQueryVirtualMemory, which shares the same origin as the R3 VirtualQueryEx.
            KSWORD_ARK_ENUMERATE_PROCESS_VAD_REQUEST request{};
            request.flags = getOptionU32(kArgs, L"--flags", 0U);
            request.processId = requireOptionU32(kArgs, L"--pid");
            request.maxEntries = getOptionU32(kArgs, L"--max-entries", KSWORD_ARK_INJECTION_VAD_LIMIT_DEFAULT);
            request.startAddress = getOptionU64(kArgs, L"--start", 0ULL);
            request.endAddress = getOptionU64(kArgs, L"--end", 0ULL);
            request.cursorVpn = getOptionU64(kArgs, L"--cursor-vpn", 0ULL);
            const std::uint32_t kLimit = getOptionU32(kArgs, L"--limit", 64U);
            std::vector<std::uint8_t> buffer(kHugeResponseBytes, 0U);
            const int kRc = sendRawIoctl(L"IOCTL_KSWORD_ARK_ENUMERATE_PROCESS_VAD", IOCTL_KSWORD_ARK_ENUMERATE_PROCESS_VAD, &request, sizeof(request), buffer, io);
            if (kRc != 0) return normalizeIoctlRc(L"memory enum-vad", io, kRc);
            constexpr std::size_t kHeaderSize = KSWORD_ARK_INJECTION_VAD_RESPONSE_HEADER_SIZE;
            if (io.bytesReturned < kHeaderSize) { std::wcerr << L"error: enum-vad response too small\n"; return 4; }
            const auto* response = reinterpret_cast<const KSWORD_ARK_ENUMERATE_PROCESS_VAD_RESPONSE*>(buffer.data());
            std::size_t available = 0U;
            try { available = validateVariable(io.bytesReturned, kHeaderSize, response->entrySize, sizeof(KSWORD_ARK_PROCESS_VAD_ENTRY), L"enum-vad"); }
            catch (...) { return 4; }
            printResponseBanner(response->version, response->status, response->lastStatus, io.bytesReturned);
            std::wcout << L"pid=" << response->processId
                       << L" fields=0x" << std::hex << response->fieldFlags << std::dec
                       << L" returned=" << response->returnedCount
                       << L" visited=" << response->visitedCount
                       << L" unreadable=" << response->unreadableNodeCount
                       << L" profileVerified=" << response->profileVerified
                       << L" vadRootOffset=" << response->vadRootOffset
                       << L" vadRoot=" << hex64(response->vadRootAddress)
                       << L" nextCursorVpn=" << hex64(response->nextCursorVpn) << L"\n";
            // Readings from the broken-link check. When integrityValid=0, the following three fields must
            // not be used for judgment; in partial traversal, visited is naturally less than vadCount.
            std::wcout << L"  integrityValid="
                       << (((response->fieldFlags &
                             KSWORD_ARK_INJECTION_FIELD_INTEGRITY_VALID) != 0UL) ? 1 : 0)
                       << L" vadCount=" << response->vadCount
                       << L" vadCountKnown="
                       << (((response->fieldFlags &
                             KSWORD_ARK_INJECTION_FIELD_VAD_COUNT_PRESENT) != 0UL) ? 1 : 0)
                       << L" parentMismatch=" << response->parentMismatchNodes
                       << L" vadHint=" << hex64(response->vadHintAddress)
                       << L" vadHintVisited=" << response->vadHintVisited
                       << L" vadHintKnown="
                       << (((response->fieldFlags &
                             KSWORD_ARK_INJECTION_FIELD_VAD_HINT_PRESENT) != 0UL) ? 1 : 0)
                       << L"\n";
            const std::size_t kParsed = responseCountLimit(response->returnedCount, available, kLimit);
            for (std::size_t i = 0; i < kParsed; ++i)
            {
                const auto* entry = reinterpret_cast<const KSWORD_ARK_PROCESS_VAD_ENTRY*>(buffer.data() + kHeaderSize + (i * response->entrySize));
                std::wcout << L"  [" << i << L"] " << hex64(entry->startVa)
                           << L"-" << hex64(entry->endVaExclusive)
                           << L" node=" << hex64(entry->vadNodeAddress)
                           << L" subsection=" << hex64(entry->subsection)
                           << L" flagsRaw=0x" << std::hex << entry->vadFlagsRaw
                           << L" entryFlags=0x" << entry->entryFlags << std::dec
                           << L" protection=" << entry->protection
                           << L" vadType=" << entry->vadType << L"\n";
            }
            return 0;
        }
        if (kSub == L"scan-exec-pte")
        {
            // Note: The processor determines which user pages are executed as code. This is an independent fact from the
            // protection attributes recorded in VAD/VirtualQueryEx; when inconsistent, the page table takes precedence.
            KSWORD_ARK_SCAN_PROCESS_EXECUTABLE_PTE_REQUEST request{};
            request.flags = getOptionU32(kArgs, L"--flags", 0U);
            request.processId = requireOptionU32(kArgs, L"--pid");
            request.maxEntries = getOptionU32(kArgs, L"--max-entries", KSWORD_ARK_INJECTION_PTE_LIMIT_DEFAULT);
            request.maxTableReads = getOptionU32(kArgs, L"--max-table-reads", KSWORD_ARK_INJECTION_PTE_TABLE_READS_DEFAULT);
            request.startAddress = getOptionU64(kArgs, L"--start", 0ULL);
            request.endAddress = getOptionU64(kArgs, L"--end", 0ULL);
            request.cursorAddress = getOptionU64(kArgs, L"--cursor", 0ULL);
            const std::uint32_t kLimit = getOptionU32(kArgs, L"--limit", 64U);
            std::vector<std::uint8_t> buffer(kHugeResponseBytes, 0U);
            const int kRc = sendRawIoctl(L"IOCTL_KSWORD_ARK_SCAN_PROCESS_EXECUTABLE_PTE", IOCTL_KSWORD_ARK_SCAN_PROCESS_EXECUTABLE_PTE, &request, sizeof(request), buffer, io);
            if (kRc != 0) return normalizeIoctlRc(L"memory scan-exec-pte", io, kRc);
            constexpr std::size_t kHeaderSize = KSWORD_ARK_INJECTION_PTE_RESPONSE_HEADER_SIZE;
            if (io.bytesReturned < kHeaderSize) { std::wcerr << L"error: scan-exec-pte response too small\n"; return 4; }
            const auto* response = reinterpret_cast<const KSWORD_ARK_SCAN_PROCESS_EXECUTABLE_PTE_RESPONSE*>(buffer.data());
            std::size_t available = 0U;
            try { available = validateVariable(io.bytesReturned, kHeaderSize, response->entrySize, sizeof(KSWORD_ARK_PROCESS_EXECUTABLE_PTE_ENTRY), L"scan-exec-pte"); }
            catch (...) { return 4; }
            printResponseBanner(response->version, response->status, response->lastStatus, io.bytesReturned);
            std::wcout << L"pid=" << response->processId
                       << L" fields=0x" << std::hex << response->fieldFlags << std::dec
                       << L" returned=" << response->returnedCount
                       << L" tableReads=" << response->tableReads
                       << L" failedTableReads=" << response->failedTableReads
                       << L" execPages=" << response->executablePageCount
                       << L" scanned=" << hex64(response->scannedBegin) << L"-" << hex64(response->scannedEnd)
                       << L" nextCursor=" << hex64(response->nextCursorAddress)
                       << L" cr3=" << hex64(response->cr3PhysicalAddress) << L"\n";
            const std::size_t kParsed = responseCountLimit(response->returnedCount, available, kLimit);
            for (std::size_t i = 0; i < kParsed; ++i)
            {
                const auto* entry = reinterpret_cast<const KSWORD_ARK_PROCESS_EXECUTABLE_PTE_ENTRY*>(buffer.data() + kHeaderSize + (i * response->entrySize));
                std::wcout << L"  [" << i << L"] " << hex64(entry->startVa)
                           << L" len=" << hex64(entry->byteLength)
                           << L" pageSize=" << entry->pageSize
                           << L" pages=" << entry->pageCount
                           << L" effective=0x" << std::hex << entry->effectiveFlags
                           << L" entryFlags=0x" << entry->entryFlags
                           << L" firstPte=" << hex64(entry->firstEntryValue) << std::dec << L"\n";
            }
            return 0;
        }
        if (kSub == L"read-section-pages")
        {
            // Image section object reference pages: the copy held by the memory manager representing what it 'should be'.
            // It is an independent source from 'reading disk files' — even if the disk file is locked,
            // unreadable, or modified, this copy remains the content as it was when the mapping was established.
            KSWORD_ARK_READ_IMAGE_SECTION_PAGES_REQUEST request{};
            request.size = sizeof(request);
            request.version = KSWORD_ARK_INJECTION_SCAN_PROTOCOL_VERSION;
            request.processId = requireOptionU32(kArgs, L"--pid");
            request.flags = getOptionU32(kArgs, L"--flags", 0U);
            request.rangeStart = getOptionU64(kArgs, L"--start", 0ULL);
            request.rangeEnd = getOptionU64(kArgs, L"--end", 0ULL);
            request.cursorVa = getOptionU64(kArgs, L"--cursor", 0ULL);
            request.maxPages = getOptionU32(kArgs, L"--max-pages",
                                            KSWORD_ARK_INJECTION_SECTION_PAGES_DEFAULT);
            const std::uint32_t kLimit = getOptionU32(kArgs, L"--limit", 16U);
            std::vector<std::uint8_t> buffer(kHugeResponseBytes, 0U);
            const int kRc = sendRawIoctl(L"IOCTL_KSWORD_ARK_READ_IMAGE_SECTION_PAGES",
                                        IOCTL_KSWORD_ARK_READ_IMAGE_SECTION_PAGES,
                                        &request, sizeof(request), buffer, io);
            if (kRc != 0) return normalizeIoctlRc(L"memory read-section-pages", io, kRc);
            constexpr std::size_t kHeaderSize = KSWORD_ARK_INJECTION_SECTION_RESPONSE_HEADER_SIZE;
            if (io.bytesReturned < kHeaderSize) { std::wcerr << L"error: read-section-pages response too small\n"; return 4; }
            const auto* response = reinterpret_cast<const KSWORD_ARK_READ_IMAGE_SECTION_PAGES_RESPONSE*>(buffer.data());
            std::size_t available = 0U;
            try { available = validateVariable(io.bytesReturned, kHeaderSize, response->entrySize, sizeof(KSWORD_ARK_IMAGE_SECTION_PAGE_ENTRY), L"read-section-pages"); }
            catch (...) { return 4; }
            printResponseBanner(response->version, response->status, response->lastStatus, io.bytesReturned);
            std::wcout << L"pid=" << response->processId
                       << L" fields=0x" << std::hex << response->fieldFlags << std::dec
                       << L" returned=" << response->returnedCount
                       << L" valid=" << response->validPageCount
                       << L" notResident=" << response->notResidentPageCount
                       << L" unreadablePte=" << response->unreadablePteCount
                       << L" bytesPerPage=" << response->bytesPerPage
                       << L" controlArea=" << hex64(response->controlArea)
                       << L" segment=" << hex64(response->segment)
                       << L" protoArray=" << hex64(response->prototypePteArray)
                       << L" nextCursor=" << hex64(response->nextCursorVa) << L"\n";
            // Use the byteAreaOffset **provided by the response** for the byte area; computing it independently is incorrect:
            // It depends on the driver-side entry capacity, which is constrained by both the buffer size and maxPages.
            const std::size_t kBytesBase = static_cast<std::size_t>(response->byteAreaOffset);
            std::size_t validSeen = 0U;
            const std::size_t kParsed = responseCountLimit(response->returnedCount, available, kLimit);
            for (std::size_t i = 0; i < kParsed; ++i)
            {
                const auto* entry = reinterpret_cast<const KSWORD_ARK_IMAGE_SECTION_PAGE_ENTRY*>(buffer.data() + kHeaderSize + (i * response->entrySize));
                std::wcout << L"  [" << i << L"] va=" << hex64(entry->va)
                           << L" pte=" << hex64(entry->prototypePteAddress)
                           << L" value=" << hex64(entry->prototypePteValue)
                           << L" phys=" << hex64(entry->physicalAddress)
                           << L" flags=0x" << std::hex << entry->entryFlags << std::dec;
                // Print the first 8 bytes when bytes are present. 'Bytes returned' and 'bytes are correct' are two different things;
                // reporting only the former is equivalent to not verifying the content—the image header should start with MZ (4D5A).
                if ((entry->entryFlags & KSWORD_ARK_INJECTION_SECTION_ENTRY_FLAG_BYTES_PRESENT) != 0UL &&
                    response->bytesPerPage != 0UL)
                {
                    const std::size_t kOffset = kBytesBase + (validSeen * response->bytesPerPage);
                    if (kOffset + 8U <= io.bytesReturned)
                    {
                        std::wcout << L" first8=" << std::hex << std::setfill(L'0');
                        for (std::size_t b = 0; b < 8U; ++b)
                        {
                            std::wcout << std::setw(2) << static_cast<unsigned>(buffer[kOffset + b]);
                        }
                        std::wcout << std::dec << std::setfill(L' ');
                    }
                    ++validSeen;
                }
                std::wcout << L"\n";
            }
            return 0;
        }
        std::wcerr << L"error: unknown memory subcommand '" << kSub << L"'\n";
        return 1;
    }
}

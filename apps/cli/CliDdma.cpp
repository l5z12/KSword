#include "CliSupport.h"

namespace ksword::cli
{
    // printDdmaChecks purpose: Output four-state results per acceptance agreement and provide a summary exit code.
    // Exit code: 0 = all PASS or NOT_APPLICABLE; 4 = at least one FAIL.
    // NOT_APPLICABLE does not count as a failure: 'Unable to query on this machine' and 'Query returned incorrect data' are distinct
    // issues; treating the former as FAIL would make the report never turn green, effectively rendering the report useless.
    int printDdmaChecks(const std::vector<DdmaCheck>& checks)
    {
        int failed = 0;
        int notApplicable = 0;
        std::wcout << L"== DDMA selftest ==\n";
        for (const DdmaCheck& check : checks)
        {
            std::wcout << L"[" << check.verdict << L"] " << check.name;
            if (!check.detail.empty())
            {
                std::wcout << L" -- " << check.detail;
            }
            std::wcout << L"\n";
            if (std::wstring(check.verdict) == L"FAIL") { ++failed; }
            else if (std::wstring(check.verdict) == L"NOT_APPLICABLE") { ++notApplicable; }
        }
        std::wcout << L"total=" << checks.size()
                   << L" failed=" << failed
                   << L" notApplicable=" << notApplicable << L"\n";
        std::wcout << (failed == 0 ? L"DDMA selftest: PASS\n" : L"DDMA selftest: FAIL\n");
        return failed == 0 ? 0 : 4;
    }

    // sendDdmaRead: Sends a single DDMA physical read and passes the response header to the caller.
    // Return: true indicates successful IOCTL round-trip (semantic result depends on response->readStatus).
    bool sendDdmaRead(
        const KSWORD_ARK_DDMA_READ_PHYSICAL_REQUEST& request,
        std::vector<std::uint8_t>& buffer,
        IoctlResult& io)
    {
        constexpr std::size_t kHeaderSize =
            offsetof(KSWORD_ARK_DDMA_READ_PHYSICAL_RESPONSE, data);
        buffer.assign(kHeaderSize + KSWORD_ARK_DDMA_TRANSFER_BYTES, 0U);
        const int kRc = sendRawIoctl(
            L"IOCTL_KSWORD_ARK_DDMA_READ_PHYSICAL",
            IOCTL_KSWORD_ARK_DDMA_READ_PHYSICAL,
            const_cast<KSWORD_ARK_DDMA_READ_PHYSICAL_REQUEST*>(&request),
            static_cast<DWORD>(sizeof(request)),
            buffer,
            io,
            GENERIC_READ | GENERIC_WRITE);
        return kRc == 0 && io.bytesReturned >= kHeaderSize;
    }

    // ddmaReadStatusOf: Extracts aggregated status from the read response; returns UNAVAILABLE if the response is invalid.
    unsigned long ddmaReadStatusOf(const std::vector<std::uint8_t>& buffer)
    {
        constexpr std::size_t kHeaderSize =
            offsetof(KSWORD_ARK_DDMA_READ_PHYSICAL_RESPONSE, data);
        if (buffer.size() < kHeaderSize) { return KSWORD_ARK_DDMA_READ_STATUS_UNAVAILABLE; }
        return reinterpret_cast<const KSWORD_ARK_DDMA_READ_PHYSICAL_RESPONSE*>(
            buffer.data())->readStatus;
    }

    // expectDdmaReadStatus function: Executes a read request and asserts that it falls into the expected rejection state.
    DdmaCheck expectDdmaReadStatus(
        const wchar_t* name,
        const KSWORD_ARK_DDMA_READ_PHYSICAL_REQUEST& request,
        unsigned long expectedStatus)
    {
        std::vector<std::uint8_t> buffer;
        IoctlResult io{};
        if (!sendDdmaRead(request, buffer, io))
        {
            return DdmaCheck{ name, L"FAIL",
                L"IOCTL failed, win32=" + std::to_wstring(io.win32Error) };
        }
        const unsigned long kActual = ddmaReadStatusOf(buffer);
        if (kActual == expectedStatus)
        {
            return DdmaCheck{ name, L"PASS",
                L"readStatus=" + std::to_wstring(kActual) };
        }
        return DdmaCheck{ name, L"FAIL",
            L"expected readStatus=" + std::to_wstring(expectedStatus) +
            L" got " + std::to_wstring(kActual) };
    }

    // runDdmaSelfTest purpose: Run all offline verifiable DDMA items with a single command.
    // Parameters scratchLba / hasLba: whether an explicit scratch LBA is provided (transfer probing is performed only if provided).
    int runDdmaSelfTest(std::uint64_t scratchLba, bool hasLba)
    {
        std::vector<DdmaCheck> checks;

        // ---- 1. Capability query: Whether the IOCTL is registered and whether the machine meets the conditions ----
        KSWORD_ARK_DDMA_QUERY_CAPABILITY_REQUEST queryRequest{};
        queryRequest.maxDisks = KSWORD_ARK_DDMA_DISK_LIMIT_DEFAULT;
        if (hasLba)
        {
            queryRequest.flags =
                KSWORD_ARK_DDMA_QUERY_FLAG_PROBE_TRANSFER |
                KSWORD_ARK_DDMA_FLAG_SCRATCH_LBA_VALID;
            queryRequest.scratchLba = scratchLba;
        }

        constexpr std::size_t kQueryHeaderSize =
            offsetof(KSWORD_ARK_DDMA_QUERY_CAPABILITY_RESPONSE, entries);
        std::vector<std::uint8_t> queryBuffer(
            kQueryHeaderSize +
                (KSWORD_ARK_DDMA_DISK_LIMIT_DEFAULT * sizeof(KSWORD_ARK_DDMA_DISK_ENTRY)),
            0U);
        IoctlResult queryIo{};
        const int kQueryRc = sendRawIoctl(
            L"IOCTL_KSWORD_ARK_DDMA_QUERY_CAPABILITY",
            IOCTL_KSWORD_ARK_DDMA_QUERY_CAPABILITY,
            &queryRequest,
            static_cast<DWORD>(sizeof(queryRequest)),
            queryBuffer,
            queryIo,
            GENERIC_READ | GENERIC_WRITE);

        if (kQueryRc != 0 || queryIo.bytesReturned < kQueryHeaderSize)
        {
            // When all IOCTLs FAIL to send, subsequent items are meaningless. Report the failure directly and stop; do
            // not use a string of FAILs to obscure the fact that the driver does not have this interface installed.
            checks.push_back(DdmaCheck{ L"ddma query-capability IOCTL is registered", L"FAIL",
                L"win32=" + std::to_wstring(queryIo.win32Error) +
                L" bytesReturned=" + std::to_wstring(queryIo.bytesReturned) });
            return printDdmaChecks(checks);
        }
        checks.push_back(DdmaCheck{ L"ddma query-capability IOCTL is registered", L"PASS", L"" });

        const auto* queryResponse =
            reinterpret_cast<const KSWORD_ARK_DDMA_QUERY_CAPABILITY_RESPONSE*>(queryBuffer.data());
        const bool kKernelDebugger =
            (queryResponse->capabilityFlags & KSWORD_ARK_DDMA_CAP_FLAG_KERNEL_DEBUGGER_ENABLED) != 0UL;
        const bool kDiskDriverPresent =
            (queryResponse->capabilityFlags & KSWORD_ARK_DDMA_CAP_FLAG_DISK_DRIVER_PRESENT) != 0UL;

        checks.push_back(DdmaCheck{ L"protocol version matches this build",
            (queryResponse->version == KSWORD_ARK_DDMA_PROTOCOL_VERSION) ? L"PASS" : L"FAIL",
            L"version=" + std::to_wstring(queryResponse->version) });
        checks.push_back(DdmaCheck{ L"transfer granularity is one page",
            (queryResponse->transferBytes == KSWORD_ARK_DDMA_TRANSFER_BYTES) ? L"PASS" : L"FAIL",
            L"transferBytes=" + std::to_wstring(queryResponse->transferBytes) +
            L" scratchSectors=" + std::to_wstring(queryResponse->scratchSectorCount) });
        checks.push_back(DdmaCheck{ L"kernel-debugger hazard is reported", L"PASS",
            kKernelDebugger
                ? std::wstring(L"kernel debugging ENABLED -- DDMA transfers must stay blocked")
                : std::wstring(L"kernel debugging disabled") });
        checks.push_back(DdmaCheck{ L"\\Driver\\Disk was reachable",
            kDiskDriverPresent ? L"PASS" : L"FAIL",
            L"status=" + std::to_wstring(queryResponse->status) +
            L" totalDisks=" + std::to_wstring(queryResponse->totalDisks) });

        // Whether ATA passthrough is usable is a machine attribute, not a code correctness issue. If unavailable,
        // report NOT_APPLICABLE, not FAIL; marking it as FAIL would cause reports on Gen2 VMs to never turn green.
        if (!hasLba)
        {
            checks.push_back(DdmaCheck{ L"ATA DMA transfer probe", L"NOT_APPLICABLE",
                L"no --lba given, so no transfer probe was issued" });
        }
        else if (queryResponse->readyDisks == 0UL)
        {
            checks.push_back(DdmaCheck{ L"ATA DMA transfer probe", L"NOT_APPLICABLE",
                L"no disk accepted IOCTL_ATA_PASS_THROUGH_DIRECT (expected on synthetic SCSI, e.g. Hyper-V Gen2)" });
        }
        else
        {
            checks.push_back(DdmaCheck{ L"ATA DMA transfer probe", L"PASS",
                L"readyDisks=" + std::to_wstring(queryResponse->readyDisks) });
        }

        for (unsigned long index = 0UL; index < queryResponse->returnedDisks; ++index)
        {
            const KSWORD_ARK_DDMA_DISK_ENTRY& entry = queryResponse->entries[index];
            std::wcout << L"  disk[" << entry.deviceIndex << L"] flags=0x" << std::hex
                       << entry.diskFlags << std::dec
                       << L" probeStatus=0x" << std::hex
                       << static_cast<unsigned long>(entry.probeStatus) << std::dec
                       << L" name=" << entry.deviceName << L"\n";
        }

        // ---- 2. Access Control: The three rejection paths must return three distinct status codes.
        // These requests are rejected before the driver encounters any disk, writing zero bytes.
        const std::uint32_t kUnreachableDisk = 0xFFFFFFFFUL;

        {
            KSWORD_ARK_DDMA_READ_PHYSICAL_REQUEST request{};
            request.diskIndex = kUnreachableDisk;
            request.physicalAddress = 0x1000ULL;
            request.bytesToRead = 64UL;
            request.flags = KSWORD_ARK_DDMA_FLAG_SCRATCH_ACKNOWLEDGED;
            checks.push_back(expectDdmaReadStatus(
                L"read without SCRATCH_LBA_VALID is refused",
                request,
                KSWORD_ARK_DDMA_READ_STATUS_SCRATCH_LBA_REQUIRED));
        }
        {
            KSWORD_ARK_DDMA_READ_PHYSICAL_REQUEST request{};
            request.diskIndex = kUnreachableDisk;
            request.physicalAddress = 0x1000ULL;
            request.bytesToRead = 64UL;
            request.flags = KSWORD_ARK_DDMA_FLAG_SCRATCH_LBA_VALID;
            request.scratchLba = hasLba ? scratchLba : 0x1000ULL;
            checks.push_back(expectDdmaReadStatus(
                L"read without SCRATCH_ACKNOWLEDGED is refused",
                request,
                KSWORD_ARK_DDMA_READ_STATUS_SCRATCH_NOT_ACKNOWLEDGED));
        }
        {
            // This is a regression guard for the "LBA 0 as sentinel" trap: LBA 0 is a valid
            // value, so setting the VALID bit should not cause it to be treated as "LBA not
            // filled." Using a non-existent disk index ensures the driver stops at DISK_NOT_FOUND
            // immediately after passing the LBA check, without touching any real sectors.
            KSWORD_ARK_DDMA_READ_PHYSICAL_REQUEST request{};
            request.diskIndex = kUnreachableDisk;
            request.physicalAddress = 0x1000ULL;
            request.bytesToRead = 64UL;
            request.flags =
                KSWORD_ARK_DDMA_FLAG_SCRATCH_LBA_VALID |
                KSWORD_ARK_DDMA_FLAG_SCRATCH_ACKNOWLEDGED;
            request.scratchLba = 0ULL;
            checks.push_back(expectDdmaReadStatus(
                L"scratch LBA 0 is a real value, not an unset sentinel",
                request,
                KSWORD_ARK_DDMA_READ_STATUS_DISK_NOT_FOUND));
        }
        {
            // Note: Cross-page requests must be rejected before hitting the disk.
            KSWORD_ARK_DDMA_READ_PHYSICAL_REQUEST request{};
            request.diskIndex = kUnreachableDisk;
            request.physicalAddress = 0x1FFFULL;
            request.bytesToRead = 64UL;
            request.flags =
                KSWORD_ARK_DDMA_FLAG_SCRATCH_LBA_VALID |
                KSWORD_ARK_DDMA_FLAG_SCRATCH_ACKNOWLEDGED;
            request.scratchLba = hasLba ? scratchLba : 0x1000ULL;
            checks.push_back(expectDdmaReadStatus(
                L"page-crossing range is refused",
                request,
                KSWORD_ARK_DDMA_READ_STATUS_RANGE_REJECTED));
        }
        {
            // Unknown flag bits must be rejected by the handler as parameter errors,
            // manifesting as a direct IOCTL failure rather than a response with a status code.
            KSWORD_ARK_DDMA_READ_PHYSICAL_REQUEST request{};
            request.diskIndex = kUnreachableDisk;
            request.physicalAddress = 0x1000ULL;
            request.bytesToRead = 64UL;
            request.flags = 0x80000000UL;
            std::vector<std::uint8_t> buffer;
            IoctlResult io{};
            const bool kOk = sendDdmaRead(request, buffer, io);
            checks.push_back(DdmaCheck{ L"unknown flag bits are refused",
                kOk ? L"FAIL" : L"PASS",
                L"win32=" + std::to_wstring(io.win32Error) });
        }
        {
            // Third gate of the write path: reject if LBA and confirmation are present but
            // FORCE is missing, and the status code must differ from the first two gates.
            KSWORD_ARK_DDMA_WRITE_PHYSICAL_REQUEST header{};
            constexpr std::size_t kWriteHeaderSize =
                offsetof(KSWORD_ARK_DDMA_WRITE_PHYSICAL_REQUEST, data);
            std::vector<std::uint8_t> writeRequest(kWriteHeaderSize + 4U, 0U);
            auto* request =
                reinterpret_cast<KSWORD_ARK_DDMA_WRITE_PHYSICAL_REQUEST*>(writeRequest.data());
            (void)header;
            request->diskIndex = kUnreachableDisk;
            request->physicalAddress = 0x1000ULL;
            request->bytesToWrite = 4UL;
            request->flags =
                KSWORD_ARK_DDMA_FLAG_SCRATCH_LBA_VALID |
                KSWORD_ARK_DDMA_FLAG_SCRATCH_ACKNOWLEDGED;
            request->scratchLba = hasLba ? scratchLba : 0x1000ULL;

            KSWORD_ARK_DDMA_WRITE_PHYSICAL_RESPONSE response{};
            IoctlResult io{};
            std::vector<std::uint8_t> outBuffer(sizeof(response), 0U);
            const int kRc = sendRawIoctl(
                L"IOCTL_KSWORD_ARK_DDMA_WRITE_PHYSICAL",
                IOCTL_KSWORD_ARK_DDMA_WRITE_PHYSICAL,
                writeRequest.data(),
                static_cast<DWORD>(writeRequest.size()),
                outBuffer,
                io,
                GENERIC_READ | GENERIC_WRITE);
            if (kRc != 0 || io.bytesReturned < sizeof(response))
            {
                checks.push_back(DdmaCheck{ L"write without FORCE is refused", L"FAIL",
                    L"IOCTL failed, win32=" + std::to_wstring(io.win32Error) });
            }
            else
            {
                const auto* writeResponse =
                    reinterpret_cast<const KSWORD_ARK_DDMA_WRITE_PHYSICAL_RESPONSE*>(outBuffer.data());
                const bool kExpected =
                    writeResponse->writeStatus == KSWORD_ARK_DDMA_WRITE_STATUS_FORCE_REQUIRED;
                checks.push_back(DdmaCheck{ L"write without FORCE is refused",
                    kExpected ? L"PASS" : L"FAIL",
                    L"writeStatus=" + std::to_wstring(writeResponse->writeStatus) });
            }
        }

        return printDdmaChecks(checks);
    }

    // commandDdmaFamily: Entry point for the ddma command family.
    int commandDdmaFamily(int argc, wchar_t* argv[])
    {
        if (argc < 3) { std::wcerr << L"error: ddma requires a subcommand\n"; return 1; }
        const std::wstring kSub = argv[2];
        const NamedArgs kArgs = parseNamedArgs(argc, argv, 3);
        IoctlResult io{};

        if (kSub == L"selftest")
        {
            const bool kHasLba = getOptionBool(kArgs, L"--lba");
            const std::uint64_t kLba = kHasLba ? requireOptionU64(kArgs, L"--lba") : 0ULL;
            return runDdmaSelfTest(kLba, kHasLba);
        }

        if (kSub == L"probe")
        {
            KSWORD_ARK_DDMA_QUERY_CAPABILITY_REQUEST request{};
            request.maxDisks = getOptionU32(kArgs, L"--max-disks", KSWORD_ARK_DDMA_DISK_LIMIT_DEFAULT);
            const bool kHasLba = getOptionBool(kArgs, L"--lba");
            if (kHasLba)
            {
                request.flags =
                    KSWORD_ARK_DDMA_QUERY_FLAG_PROBE_TRANSFER |
                    KSWORD_ARK_DDMA_FLAG_SCRATCH_LBA_VALID;
                request.scratchLba = requireOptionU64(kArgs, L"--lba");
            }

            constexpr std::size_t kHeaderSize =
                offsetof(KSWORD_ARK_DDMA_QUERY_CAPABILITY_RESPONSE, entries);
            std::vector<std::uint8_t> buffer(
                kHeaderSize + (KSWORD_ARK_DDMA_DISK_LIMIT_HARD * sizeof(KSWORD_ARK_DDMA_DISK_ENTRY)),
                0U);
            const int kRc = sendRawIoctl(
                L"IOCTL_KSWORD_ARK_DDMA_QUERY_CAPABILITY",
                IOCTL_KSWORD_ARK_DDMA_QUERY_CAPABILITY,
                &request,
                static_cast<DWORD>(sizeof(request)),
                buffer,
                io,
                GENERIC_READ | GENERIC_WRITE);
            if (kRc != 0) { return normalizeIoctlRc(L"ddma probe", io, kRc); }
            if (io.bytesReturned < kHeaderSize)
            {
                std::wcerr << L"error: ddma probe response too small\n";
                return 4;
            }
            const auto* response =
                reinterpret_cast<const KSWORD_ARK_DDMA_QUERY_CAPABILITY_RESPONSE*>(buffer.data());
            std::wcout << L"version=" << response->version
                       << L" status=" << response->status
                       << L" capabilityFlags=0x" << std::hex << response->capabilityFlags << std::dec
                       << L" totalDisks=" << response->totalDisks
                       << L" readyDisks=" << response->readyDisks
                       << L" transferBytes=" << response->transferBytes
                       << L" scratchSectors=" << response->scratchSectorCount
                       << L" lastStatus=0x" << std::hex
                       << static_cast<unsigned long>(response->lastStatus) << std::dec << L"\n";
            if ((response->capabilityFlags & KSWORD_ARK_DDMA_CAP_FLAG_KERNEL_DEBUGGER_ENABLED) != 0UL)
            {
                std::wcout << L"WARNING: kernel debugging is enabled; DDMA transfers would hit "
                              L"MiShowBadMapper and bugcheck.\n";
            }
            for (unsigned long index = 0UL; index < response->returnedDisks; ++index)
            {
                const KSWORD_ARK_DDMA_DISK_ENTRY& entry = response->entries[index];
                std::wcout << L"  disk[" << entry.deviceIndex << L"]"
                           << L" flags=0x" << std::hex << entry.diskFlags << std::dec
                           << L" sectorSize=" << entry.sectorSize
                           << L" probeStatus=0x" << std::hex
                           << static_cast<unsigned long>(entry.probeStatus) << std::dec
                           << L" name=" << entry.deviceName << L"\n";
            }
            return 0;
        }

        if (kSub == L"read")
        {
            KSWORD_ARK_DDMA_READ_PHYSICAL_REQUEST request{};
            request.diskIndex = requireOptionU32(kArgs, L"--disk");
            request.physicalAddress = requireOptionU64(kArgs, L"--pa");
            request.bytesToRead = getOptionU32(kArgs, L"--bytes", 64U);
            request.scratchLba = requireOptionU64(kArgs, L"--lba");
            // Read operations also overwrite scratch sectors, so the confirmation flag is required, not optional.
            request.flags =
                KSWORD_ARK_DDMA_FLAG_UI_CONFIRMED |
                KSWORD_ARK_DDMA_FLAG_SCRATCH_LBA_VALID |
                KSWORD_ARK_DDMA_FLAG_SCRATCH_ACKNOWLEDGED;

            std::vector<std::uint8_t> buffer;
            if (!sendDdmaRead(request, buffer, io))
            {
                return normalizeIoctlRc(L"ddma read", io, 3);
            }
            constexpr std::size_t kHeaderSize =
                offsetof(KSWORD_ARK_DDMA_READ_PHYSICAL_RESPONSE, data);
            const auto* response =
                reinterpret_cast<const KSWORD_ARK_DDMA_READ_PHYSICAL_RESPONSE*>(buffer.data());
            std::wcout << L"readStatus=" << response->readStatus
                       << L" bytesRead=" << response->bytesRead
                       << L" fieldFlags=0x" << std::hex << response->fieldFlags << std::dec
                       << L" map=0x" << std::hex << static_cast<unsigned long>(response->mapStatus)
                       << L" backup=0x" << static_cast<unsigned long>(response->backupStatus)
                       << L" stageOut=0x" << static_cast<unsigned long>(response->stageOutStatus)
                       << L" stageIn=0x" << static_cast<unsigned long>(response->stageInStatus)
                       << L" restore=0x" << static_cast<unsigned long>(response->restoreStatus)
                       << std::dec << L"\n";
            if ((response->fieldFlags & KSWORD_ARK_DDMA_FIELD_SCRATCH_RESTORED) == 0UL &&
                response->backupStatus != static_cast<long>(0xC00000BBL))
            {
                std::wcout << L"WARNING: scratch sectors were NOT restored; the disk is left dirty.\n";
            }
            if (response->bytesRead > 0UL)
            {
                hexdump(buffer.data() + kHeaderSize, response->bytesRead);
            }
            return 0;
        }

        std::wcerr << L"error: unknown ddma subcommand '" << kSub << L"'\n";
        return 1;
    }
}

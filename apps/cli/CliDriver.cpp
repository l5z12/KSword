#include "CliSupport.h"

namespace ksword::cli
{
    // queryDriverOptionalGlobalEvidence: Reuses optional global evidence from Driver Integrity.
    // Input: CLI arguments, command label, detail filter keyword, and display name.
    // Processing: Read-only query of OPTIONAL_GLOBALS; do not add new protocols or enumerate/modify kernel table contents.
    // Returns: 0 indicates successful printing of R0 evidence; 5 indicates the old driver does not support or failed to return the target evidence.
    int queryDriverOptionalGlobalEvidence(
        const NamedArgs& args,
        const wchar_t* featureLabel,
        const wchar_t* detailNeedle,
        const wchar_t* displayName)
    {
        KSWORD_ARK_QUERY_DRIVER_INTEGRITY_REQUEST request{};
        request.version = KSWORD_ARK_DRIVER_INTEGRITY_PROTOCOL_VERSION;
        request.flags =
            getOptionU32(args, L"--flags", KSWORD_ARK_DRIVER_INTEGRITY_FLAG_OPTIONAL_GLOBALS) |
            KSWORD_ARK_DRIVER_INTEGRITY_FLAG_OPTIONAL_GLOBALS;
        request.maxRows = getOptionU32(args, L"--max-rows", 32U);
        request.maxIdtVectorsPerCpu = getOptionU32(args, L"--max-idt-vectors", 0U);
        request.maxDevices = getOptionU32(args, L"--max-devices", 0U);
        request.maxAttachedDevices = getOptionU32(args, L"--max-attached", 0U);
        request.targetModuleBase = getOptionU64(args, L"--module-base", 0ULL);

        IoctlResult io{};
        std::vector<std::uint8_t> buffer(kLargeResponseBytes, 0U);
        const int kRc = sendRawIoctl(
            L"IOCTL_KSWORD_ARK_QUERY_DRIVER_INTEGRITY",
            IOCTL_KSWORD_ARK_QUERY_DRIVER_INTEGRITY,
            &request,
            sizeof(request),
            buffer,
            io);
        if (kRc != 0)
        {
            return normalizeIoctlRc(featureLabel, io, kRc);
        }

        constexpr std::size_t kHeaderSize =
            sizeof(KSWORD_ARK_QUERY_DRIVER_INTEGRITY_RESPONSE) -
            sizeof(KSWORD_ARK_DRIVER_INTEGRITY_EVIDENCE);
        const auto* response =
            reinterpret_cast<const KSWORD_ARK_QUERY_DRIVER_INTEGRITY_RESPONSE*>(buffer.data());
        std::size_t available = 0U;
        try
        {
            available = validateVariable(
                io.bytesReturned,
                kHeaderSize,
                response->entrySize,
                sizeof(KSWORD_ARK_DRIVER_INTEGRITY_EVIDENCE),
                featureLabel);
        }
        catch (...)
        {
            return 4;
        }

        printResponseBanner(response->version, response->queryStatus, response->lastStatus, io.bytesReturned);
        printCountHeader(response->version, response->totalCount, response->returnedCount, response->entrySize, io.bytesReturned);
        std::wcout << L"projection=" << displayName
                   << L" source=driver-integrity optional-globals"
                   << L" fieldFlags=0x" << std::hex << response->fieldFlags
                   << L" statusFlags=0x" << response->statusFlags
                   << std::dec << L"\n";

        const std::size_t kLimit = getOptionU32(args, L"--limit", 16U);
        const std::size_t kParsed = responseCountLimit(response->returnedCount, available, kLimit);
        std::size_t matchedCount = 0U;
        for (std::size_t index = 0U; index < kParsed; ++index)
        {
            const auto* entry = reinterpret_cast<const KSWORD_ARK_DRIVER_INTEGRITY_EVIDENCE*>(
                buffer.data() + kHeaderSize + (index * response->entrySize));
            const std::wstring kDetailText = fixedWide(entry->detail, KSWORD_ARK_DRIVER_INTEGRITY_DETAIL_CHARS);
            const bool kOptionalGlobalRow =
                entry->evidenceClass == KSWORD_ARK_DRIVER_INTEGRITY_CLASS_OPTIONAL_GLOBAL;
            if (!kOptionalGlobalRow || !containsIgnoreCase(kDetailText, detailNeedle))
            {
                continue;
            }

            ++matchedCount;
            std::wcout << L"  [" << index << L"] class=" << entry->evidenceClass
                       << L" statusFlags=0x" << std::hex << entry->statusFlags
                       << L" risk=0x" << entry->riskFlags
                       << L" fieldMask=0x" << entry->fieldMask
                       << L" object=" << hex64(entry->objectAddress)
                       << L" target=" << hex64(entry->targetAddress)
                       << L" ownerBase=" << hex64(entry->ownerModuleBase)
                       << std::dec << L" confidence=" << entry->confidence
                       << L" owner='" << fixedWide(entry->ownerModule, KSWORD_ARK_DRIVER_INTEGRITY_OWNER_CHARS)
                       << L"' detail='" << kDetailText << L"'\n";
        }

        if (matchedCount == 0U)
        {
            std::wcout << L"unsupported / unavailable: " << featureLabel
                       << L" (Driver Integrity returned no matching optional-global evidence for "
                       << displayName << L")\n";
            return 5;
        }
        return 0;
    }

    // commandDriverFamily exposes driver audit aliases requested by PDB R0 work.
    // Inputs: argc/argv from wmain.
    // Processing: routes read-only aliases to existing kernel/storage queries.
    // Returns: process exit code.
    int commandDriverFamily(int argc, wchar_t* argv[])
    {
        if (argc < 3) { std::wcerr << L"error: driver requires a subcommand\n"; return 1; }
        const std::wstring kSub = argv[2];
        const NamedArgs kArgs = parseNamedArgs(argc, argv, 3);
        if (kSub == L"integrity")
        {
            KSWORD_ARK_QUERY_DRIVER_INTEGRITY_REQUEST request{};
            request.version = KSWORD_ARK_DRIVER_INTEGRITY_PROTOCOL_VERSION;
            request.flags = getOptionU32(kArgs, L"--flags", KSWORD_ARK_DRIVER_INTEGRITY_FLAG_DEFAULT);
            request.maxRows = getOptionU32(kArgs, L"--max-rows", KSWORD_ARK_DRIVER_INTEGRITY_DEFAULT_MAX_ROWS);
            request.maxIdtVectorsPerCpu = getOptionU32(kArgs, L"--max-idt-vectors", KSWORD_ARK_DRIVER_INTEGRITY_DEFAULT_IDT_VECTORS);
            request.maxDevices = getOptionU32(kArgs, L"--max-devices", KSWORD_ARK_DRIVER_DEVICE_LIMIT_DEFAULT);
            request.maxAttachedDevices = getOptionU32(kArgs, L"--max-attached", KSWORD_ARK_DRIVER_ATTACHED_LIMIT_DEFAULT);
            request.targetModuleBase = getOptionU64(kArgs, L"--module-base", 0ULL);
            copyOptionalWideOption(kArgs, L"--driver", request.driverName, KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS);
            IoctlResult io{};
            std::vector<std::uint8_t> buffer(kLargeResponseBytes, 0U);
            const int kRc = sendRawIoctl(L"IOCTL_KSWORD_ARK_QUERY_DRIVER_INTEGRITY", IOCTL_KSWORD_ARK_QUERY_DRIVER_INTEGRITY, &request, sizeof(request), buffer, io);
            if (kRc != 0) return normalizeIoctlRc(L"driver integrity", io, kRc);
            constexpr std::size_t kHeaderSize = sizeof(KSWORD_ARK_QUERY_DRIVER_INTEGRITY_RESPONSE) - sizeof(KSWORD_ARK_DRIVER_INTEGRITY_EVIDENCE);
            const auto* response = reinterpret_cast<const KSWORD_ARK_QUERY_DRIVER_INTEGRITY_RESPONSE*>(buffer.data());
            std::size_t available = 0U;
            try { available = validateVariable(io.bytesReturned, kHeaderSize, response->entrySize, sizeof(KSWORD_ARK_DRIVER_INTEGRITY_EVIDENCE), L"driver integrity"); }
            catch (...) { return 4; }
            printResponseBanner(response->version, response->queryStatus, response->lastStatus, io.bytesReturned);
            printCountHeader(response->version, response->totalCount, response->returnedCount, response->entrySize, io.bytesReturned);
            std::wcout << L"fieldFlags=0x" << std::hex << response->fieldFlags
                       << L" statusFlags=0x" << response->statusFlags
                       << L" sourceMask=0x" << response->sourceMask
                       << std::dec << L" cpuCount=" << response->cpuCount
                       << L" moduleCount=" << response->moduleCount << L"\n";
            const std::size_t kParsed = responseCountLimit(response->returnedCount, available, getOptionU32(kArgs, L"--limit", 128U));
            for (std::size_t i = 0; i < kParsed; ++i)
            {
                const auto* entry = reinterpret_cast<const KSWORD_ARK_DRIVER_INTEGRITY_EVIDENCE*>(buffer.data() + kHeaderSize + (i * response->entrySize));
                std::wcout << L"  [" << i << L"] class=" << entry->evidenceClass
                           << L" risk=0x" << std::hex << entry->riskFlags
                           << L" source=0x" << entry->sourceMask
                           << L" object=" << hex64(entry->objectAddress)
                           << L" target=" << hex64(entry->targetAddress)
                           << L" ownerBase=" << hex64(entry->ownerModuleBase)
                           << std::dec << L" confidence=" << entry->confidence
                           << L" owner='" << fixedWide(entry->ownerModule, KSWORD_ARK_DRIVER_INTEGRITY_OWNER_CHARS)
                           << L"' detail='" << fixedWide(entry->detail, KSWORD_ARK_DRIVER_INTEGRITY_DETAIL_CHARS) << L"'\n";
            }
            return 0;
        }
        if (kSub == L"detail")
        {
            KSWORD_ARK_QUERY_DRIVER_OBJECT_REQUEST request{};
            request.flags = getOptionU32(kArgs, L"--flags", KSWORD_ARK_DRIVER_OBJECT_QUERY_FLAG_INCLUDE_ALL);
            request.maxDevices = getOptionU32(kArgs, L"--max-devices", KSWORD_ARK_DRIVER_DEVICE_LIMIT_DEFAULT);
            request.maxAttachedDevices = getOptionU32(kArgs, L"--max-attached", KSWORD_ARK_DRIVER_ATTACHED_LIMIT_DEFAULT);
            copyRequiredWideOption(kArgs, L"--driver", request.driverName, KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS);
            IoctlResult io{};
            std::vector<std::uint8_t> buffer(kLargeResponseBytes, 0U);
            const int kRc = sendRawIoctl(L"IOCTL_KSWORD_ARK_QUERY_DRIVER_OBJECT", IOCTL_KSWORD_ARK_QUERY_DRIVER_OBJECT, &request, sizeof(request), buffer, io);
            if (kRc != 0) return normalizeIoctlRc(L"driver detail", io, kRc);
            constexpr std::size_t kHeaderSize = sizeof(KSWORD_ARK_QUERY_DRIVER_OBJECT_RESPONSE) - sizeof(KSWORD_ARK_DRIVER_DEVICE_ENTRY);
            const auto* response = reinterpret_cast<const KSWORD_ARK_QUERY_DRIVER_OBJECT_RESPONSE*>(buffer.data());
            std::size_t available = 0U;
            try { available = validateVariable(io.bytesReturned, kHeaderSize, response->deviceEntrySize, sizeof(KSWORD_ARK_DRIVER_DEVICE_ENTRY), L"driver detail"); }
            catch (...) { return 4; }
            printResponseBanner(response->version, response->queryStatus, response->lastStatus, io.bytesReturned);
            printCountHeader(response->version, response->totalDeviceCount, response->returnedDeviceCount, response->deviceEntrySize, io.bytesReturned);
            std::wcout << L"driverObject=" << hex64(response->driverObjectAddress)
                       << L" driverStart=" << hex64(response->driverStart)
                       << L" driverSection=" << hex64(response->driverSection)
                       << L" driverUnload=" << hex64(response->driverUnload)
                       << L" driver='" << fixedWide(response->driverName, KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS)
                       << L"' service='" << fixedWide(response->serviceKeyName, KSWORD_ARK_DRIVER_SERVICE_KEY_CHARS) << L"'\n";
            const std::size_t kParsed = responseCountLimit(response->returnedDeviceCount, available, getOptionU32(kArgs, L"--limit", 64U));
            for (std::size_t i = 0; i < kParsed; ++i)
            {
                const auto* device = reinterpret_cast<const KSWORD_ARK_DRIVER_DEVICE_ENTRY*>(buffer.data() + kHeaderSize + (i * response->deviceEntrySize));
                std::wcout << L"  device[" << i << L"] depth=" << device->relationDepth
                           << L" object=" << hex64(device->deviceObjectAddress)
                           << L" attached=" << hex64(device->attachedDeviceObjectAddress)
                           << L" driver=" << hex64(device->driverObjectAddress)
                           << L" name='" << fixedWide(device->deviceName, KSWORD_ARK_DRIVER_DEVICE_NAME_CHARS) << L"'\n";
            }
            return 0;
        }
        if (kSub == L"device" || kSub == L"major" || kSub == L"fastio")
        {
            return queryDeviceAudit(kArgs, IOCTL_KSWORD_ARK_QUERY_DEVICE_STACK_AUDIT, KSWORD_ARK_DEVICE_AUDIT_PROFILE_DEVICE_STACK, L"IOCTL_KSWORD_ARK_QUERY_DEVICE_STACK_AUDIT", L"driver device");
        }
        if (kSub == L"unloaded")
        {
            return queryDriverOptionalGlobalEvidence(kArgs, L"driver unloaded", L"MmUnloadedDrivers", L"MmUnloadedDrivers");
        }
        if (kSub == L"piddb")
        {
            return queryDriverOptionalGlobalEvidence(kArgs, L"driver piddb", L"PiDDBCacheTable", L"PiDDBCacheTable");
        }
        std::wcerr << L"error: unknown driver subcommand '" << kSub << L"'\n";
        return 1;
    }
}

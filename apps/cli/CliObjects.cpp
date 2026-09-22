#include "CliSupport.h"

namespace ksword::cli
{
    // commandHandleFamily implements handle table and object queries.
    // Inputs: argc/argv from wmain.
    // Processing: queries process handles or details for one handle value.
    // Returns: process exit code.
    int commandHandleFamily(int argc, wchar_t* argv[])
    {
        if (argc < 3) { std::wcerr << L"error: handle requires a subcommand\n"; return 1; }
        const std::wstring kSub = argv[2];
        const NamedArgs kArgs = parseNamedArgs(argc, argv, 3);
        IoctlResult io{};
        if (kSub == L"enum" || kSub == L"object-table")
        {
            KSWORD_ARK_ENUM_PROCESS_HANDLES_REQUEST request{};
            request.flags = getOptionU32(kArgs, L"--flags", KSWORD_ARK_ENUM_HANDLE_FLAG_INCLUDE_ALL);
            request.processId = requireOptionU32(kArgs, L"--pid");
            std::vector<std::uint8_t> buffer(kLargeResponseBytes, 0U);
            const int kRc = sendRawIoctl(L"IOCTL_KSWORD_ARK_ENUM_PROCESS_HANDLES", IOCTL_KSWORD_ARK_ENUM_PROCESS_HANDLES, &request, sizeof(request), buffer, io);
            if (kRc != 0) return normalizeIoctlRc(L"handle object table", io, kRc);
            constexpr std::size_t kHeaderSize = sizeof(KSWORD_ARK_ENUM_PROCESS_HANDLES_RESPONSE) - sizeof(KSWORD_ARK_HANDLE_ENTRY);
            const auto* response = reinterpret_cast<const KSWORD_ARK_ENUM_PROCESS_HANDLES_RESPONSE*>(buffer.data());
            std::size_t available = 0U;
            try { available = validateVariable(io.bytesReturned, kHeaderSize, response->entrySize, sizeof(KSWORD_ARK_HANDLE_ENTRY), L"handle enum"); }
            catch (...) { return 4; }
            printResponseBanner(response->version, response->overallStatus, response->lastStatus, io.bytesReturned);
            printCountHeader(response->version, response->totalCount, response->returnedCount, response->entrySize, io.bytesReturned);
            std::wcout << L"processId=" << response->processId << L"\n";
            const std::size_t kParsed = responseCountLimit(response->returnedCount, available, getOptionU32(kArgs, L"--limit", 128U));
            for (std::size_t i = 0; i < kParsed; ++i)
            {
                const auto* entry = reinterpret_cast<const KSWORD_ARK_HANDLE_ENTRY*>(buffer.data() + kHeaderSize + (i * response->entrySize));
                std::wcout << L"  [" << i << L"] pid=" << entry->processId
                           << L" handle=0x" << std::hex << entry->handleValue
                           << L" fields=0x" << entry->fieldFlags
                           << L" access=0x" << entry->grantedAccess
                           << L" attrs=0x" << entry->attributes
                           << L" object=" << hex64(entry->objectAddress)
                           << L" dyn=0x" << entry->dynDataCapabilityMask
                           << std::dec << L" typeIndex=" << entry->objectTypeIndex
                           << L" decodeStatus=" << entry->decodeStatus << L"\n";
            }
            return 0;
        }
        if (kSub == L"query-object" || kSub == L"object-header" || kSub == L"type-matrix")
        {
            KSWORD_ARK_QUERY_HANDLE_OBJECT_REQUEST request{};
            KSWORD_ARK_QUERY_HANDLE_OBJECT_RESPONSE response{};
            request.flags = getOptionU32(kArgs, L"--flags", KSWORD_ARK_QUERY_OBJECT_FLAG_INCLUDE_ALL);
            request.processId = requireOptionU32(kArgs, L"--pid");
            request.handleValue = requireOptionU64(kArgs, L"--handle");
            request.requestedAccess = getOptionU32(kArgs, L"--access", 0U);
            if (!sendFixedRequestResponse(IOCTL_KSWORD_ARK_QUERY_HANDLE_OBJECT, L"IOCTL_KSWORD_ARK_QUERY_HANDLE_OBJECT", request, response, io))
            {
                return normalizeIoctlRc(L"handle object details", io, 3);
            }
            printResponseBanner(response.version, response.queryStatus, response.objectReferenceStatus, io.bytesReturned);
            std::wcout << L"size=" << response.size
                       << L" pid=" << response.processId
                       << L" fields=0x" << std::hex << response.fieldFlags
                       << L" handle=" << hex64(response.handleValue)
                       << L" object=" << hex64(response.objectAddress)
                       << L" dyn=0x" << response.dynDataCapabilityMask
                       << L" typeStatus=0x" << static_cast<unsigned long>(response.typeStatus)
                       << L" nameStatus=0x" << static_cast<unsigned long>(response.nameStatus)
                       << L" proxyNtStatus=0x" << static_cast<unsigned long>(response.proxyNtStatus)
                       << std::dec << L" typeIndex=" << response.objectTypeIndex
                       << L" proxyStatus=" << response.proxyStatus
                       << L" requestedAccess=" << response.requestedAccess
                       << L" actualGrantedAccess=" << response.actualGrantedAccess
                       << L" proxyHandle=" << hex64(response.proxyHandle) << L"\n";
            dumpWideText(L"typeName", fixedWide(response.typeName, KSWORD_ARK_OBJECT_TYPE_NAME_CHARS));
            dumpWideText(L"objectName", fixedWide(response.objectName, KSWORD_ARK_OBJECT_NAME_CHARS));
            return 0;
        }
        std::wcerr << L"error: unknown handle subcommand '" << kSub << L"'\n";
        return 1;
    }

    // printAlpcPortInfo renders one ALPC related-port packet.
    // Inputs: label and protocol port info.
    // Processing: prints relation, status, object pointers and optional name.
    // Returns: no value.
    void printAlpcPortInfo(const wchar_t* label, const KSWORD_ARK_ALPC_PORT_INFO& info)
    {
        std::wcout << L"  " << label
                   << L": relation=" << info.relation
                   << L" fields=0x" << std::hex << info.fieldFlags
                   << L" flags=0x" << info.flags
                   << L" object=" << hex64(info.objectAddress)
                   << L" context=" << hex64(info.portContext)
                   << L" basicStatus=0x" << static_cast<unsigned long>(info.basicStatus)
                   << L" nameStatus=0x" << static_cast<unsigned long>(info.nameStatus)
                   << std::dec << L" ownerPid=" << info.ownerProcessId
                   << L" state=" << info.state
                   << L" sequence=" << info.sequenceNo
                   << L" name='" << fixedWide(info.portName, KSWORD_ARK_ALPC_PORT_NAME_CHARS) << L"'\n";
    }

    // commandAlpcFamily implements ALPC port diagnostics.
    // Inputs: argc/argv from wmain.
    // Processing: queries an ALPC handle in a process.
    // Returns: process exit code.
    int commandAlpcFamily(int argc, wchar_t* argv[])
    {
        if (argc < 3) { std::wcerr << L"error: alpc requires a subcommand\n"; return 1; }
        const std::wstring kSub = argv[2];
        const NamedArgs kArgs = parseNamedArgs(argc, argv, 3);
        if (kSub != L"query-port")
        {
            std::wcerr << L"error: unknown alpc subcommand '" << kSub << L"'\n";
            return 1;
        }
        KSWORD_ARK_QUERY_ALPC_PORT_REQUEST request{};
        KSWORD_ARK_QUERY_ALPC_PORT_RESPONSE response{};
        request.flags = getOptionU32(kArgs, L"--flags", KSWORD_ARK_ALPC_QUERY_FLAG_INCLUDE_ALL);
        request.processId = requireOptionU32(kArgs, L"--pid");
        request.handleValue = requireOptionU64(kArgs, L"--handle");
        IoctlResult io{};
        if (!sendFixedRequestResponse(IOCTL_KSWORD_ARK_QUERY_ALPC_PORT, L"IOCTL_KSWORD_ARK_QUERY_ALPC_PORT", request, response, io)) return 3;
        printResponseBanner(response.version, response.queryStatus, response.objectReferenceStatus, io.bytesReturned);
        std::wcout << L"size=" << response.size
                   << L" pid=" << response.processId
                   << L" fields=0x" << std::hex << response.fieldFlags
                   << L" handle=" << hex64(response.handleValue)
                   << L" dyn=0x" << response.dynDataCapabilityMask
                   << L" typeStatus=0x" << static_cast<unsigned long>(response.typeStatus)
                   << L" basicStatus=0x" << static_cast<unsigned long>(response.basicStatus)
                   << L" communicationStatus=0x" << static_cast<unsigned long>(response.communicationStatus)
                   << L" nameStatus=0x" << static_cast<unsigned long>(response.nameStatus)
                   << std::dec << L" typeName='" << fixedWide(response.typeName, KSWORD_ARK_ALPC_TYPE_NAME_CHARS) << L"'\n";
        printAlpcPortInfo(L"queryPort", response.queryPort);
        printAlpcPortInfo(L"connectionPort", response.connectionPort);
        printAlpcPortInfo(L"serverPort", response.serverPort);
        printAlpcPortInfo(L"clientPort", response.clientPort);
        return 0;
    }

    // commandSectionFamily implements process and file section mapping queries.
    // Inputs: argc/argv from wmain.
    // Processing: prints variable mapping rows with bounded parsing.
    // Returns: process exit code.
    int commandSectionFamily(int argc, wchar_t* argv[])
    {
        if (argc < 3) { std::wcerr << L"error: section requires a subcommand\n"; return 1; }
        const std::wstring kSub = argv[2];
        const NamedArgs kArgs = parseNamedArgs(argc, argv, 3);
        IoctlResult io{};
        if (kSub == L"query-process")
        {
            KSWORD_ARK_QUERY_PROCESS_SECTION_REQUEST request{};
            request.flags = getOptionU32(kArgs, L"--flags", KSWORD_ARK_SECTION_QUERY_FLAG_INCLUDE_ALL);
            request.processId = requireOptionU32(kArgs, L"--pid");
            request.maxMappings = getOptionU32(kArgs, L"--max-mappings", KSWORD_ARK_SECTION_MAPPING_LIMIT_DEFAULT);
            std::vector<std::uint8_t> buffer(kLargeResponseBytes, 0U);
            const int kRc = sendRawIoctl(L"IOCTL_KSWORD_ARK_QUERY_PROCESS_SECTION", IOCTL_KSWORD_ARK_QUERY_PROCESS_SECTION, &request, sizeof(request), buffer, io);
            if (kRc != 0) return kRc;
            constexpr std::size_t kHeaderSize = sizeof(KSWORD_ARK_QUERY_PROCESS_SECTION_RESPONSE) - sizeof(KSWORD_ARK_SECTION_MAPPING_ENTRY);
            const auto* response = reinterpret_cast<const KSWORD_ARK_QUERY_PROCESS_SECTION_RESPONSE*>(buffer.data());
            std::size_t available = 0U;
            try { available = validateVariable(io.bytesReturned, kHeaderSize, response->entrySize, sizeof(KSWORD_ARK_SECTION_MAPPING_ENTRY), L"section query-process"); }
            catch (...) { return 4; }
            printResponseBanner(response->version, response->queryStatus, response->lastStatus, io.bytesReturned);
            printCountHeader(response->version, response->totalCount, response->returnedCount, response->entrySize, io.bytesReturned);
            std::wcout << L"pid=" << response->processId
                       << L" fieldFlags=0x" << std::hex << response->fieldFlags
                       << L" sectionObject=" << hex64(response->sectionObjectAddress)
                       << L" controlArea=" << hex64(response->controlAreaAddress)
                       << L" dyn=0x" << response->dynDataCapabilityMask << std::dec << L"\n";
            const std::size_t kParsed = responseCountLimit(response->returnedCount, available, getOptionU32(kArgs, L"--limit", 128U));
            for (std::size_t i = 0; i < kParsed; ++i)
            {
                const auto* entry = reinterpret_cast<const KSWORD_ARK_SECTION_MAPPING_ENTRY*>(buffer.data() + kHeaderSize + (i * response->entrySize));
                std::wcout << L"  [" << i << L"] type=" << entry->viewMapType
                           << L" pid=" << entry->processId
                           << L" start=" << hex64(entry->startVa)
                           << L" end=" << hex64(entry->endVa) << L"\n";
            }
            return 0;
        }
        if (kSub == L"query-file-mappings")
        {
            KSWORD_ARK_QUERY_FILE_SECTION_MAPPINGS_REQUEST request{};
            request.flags = getOptionU32(kArgs, L"--flags", KSWORD_ARK_FILE_SECTION_QUERY_FLAG_INCLUDE_ALL);
            request.maxMappings = getOptionU32(kArgs, L"--max-mappings", KSWORD_ARK_SECTION_MAPPING_LIMIT_DEFAULT);
            const std::wstring& path = requireOptionText(kArgs, L"--path");
            request.pathLengthChars = boundedPathLength(path, KSWORD_ARK_FILE_SECTION_PATH_MAX_CHARS);
            copyWideToFixed(request.path, KSWORD_ARK_FILE_SECTION_PATH_MAX_CHARS, path);
            std::vector<std::uint8_t> buffer(kLargeResponseBytes, 0U);
            const int kRc = sendRawIoctl(L"IOCTL_KSWORD_ARK_QUERY_FILE_SECTION_MAPPINGS", IOCTL_KSWORD_ARK_QUERY_FILE_SECTION_MAPPINGS, &request, sizeof(request), buffer, io);
            if (kRc != 0) return kRc;
            constexpr std::size_t kHeaderSize = sizeof(KSWORD_ARK_QUERY_FILE_SECTION_MAPPINGS_RESPONSE) - sizeof(KSWORD_ARK_FILE_SECTION_MAPPING_ENTRY);
            const auto* response = reinterpret_cast<const KSWORD_ARK_QUERY_FILE_SECTION_MAPPINGS_RESPONSE*>(buffer.data());
            std::size_t available = 0U;
            try { available = validateVariable(io.bytesReturned, kHeaderSize, response->entrySize, sizeof(KSWORD_ARK_FILE_SECTION_MAPPING_ENTRY), L"section query-file-mappings"); }
            catch (...) { return 4; }
            printResponseBanner(response->version, response->queryStatus, response->lastStatus, io.bytesReturned);
            printCountHeader(response->version, response->totalCount, response->returnedCount, response->entrySize, io.bytesReturned);
            std::wcout << L"fieldFlags=0x" << std::hex << response->fieldFlags
                       << L" fileObject=" << hex64(response->fileObjectAddress)
                       << L" sectionPointers=" << hex64(response->sectionObjectPointersAddress)
                       << L" dataControlArea=" << hex64(response->dataControlAreaAddress)
                       << L" imageControlArea=" << hex64(response->imageControlAreaAddress)
                       << L" dyn=0x" << response->dynDataCapabilityMask << std::dec << L"\n";
            const std::size_t kParsed = responseCountLimit(response->returnedCount, available, getOptionU32(kArgs, L"--limit", 128U));
            for (std::size_t i = 0; i < kParsed; ++i)
            {
                const auto* entry = reinterpret_cast<const KSWORD_ARK_FILE_SECTION_MAPPING_ENTRY*>(buffer.data() + kHeaderSize + (i * response->entrySize));
                std::wcout << L"  [" << i << L"] sectionKind=" << entry->sectionKind
                           << L" type=" << entry->viewMapType
                           << L" pid=" << entry->processId
                           << L" controlArea=" << hex64(entry->controlAreaAddress)
                           << L" start=" << hex64(entry->startVa)
                           << L" end=" << hex64(entry->endVa) << L"\n";
            }
            return 0;
        }
        std::wcerr << L"error: unknown section subcommand '" << kSub << L"'\n";
        return 1;
    }

    // commandWslFamily implements WSL silo diagnostics.
    // Inputs: argc/argv from wmain.
    // Processing: sends pid/tid query and prints the fixed response.
    // Returns: process exit code.
    int commandWslFamily(int argc, wchar_t* argv[])
    {
        if (argc < 3) { std::wcerr << L"error: wsl requires a subcommand\n"; return 1; }
        const std::wstring kSub = argv[2];
        const NamedArgs kArgs = parseNamedArgs(argc, argv, 3);
        if (kSub != L"query-silo")
        {
            std::wcerr << L"error: unknown wsl subcommand '" << kSub << L"'\n";
            return 1;
        }
        KSWORD_ARK_QUERY_WSL_SILO_REQUEST request{};
        KSWORD_ARK_QUERY_WSL_SILO_RESPONSE response{};
        request.flags = getOptionU32(kArgs, L"--flags", KSWORD_ARK_WSL_QUERY_FLAG_INCLUDE_ALL);
        request.processId = getOptionU32(kArgs, L"--pid", 0U);
        request.threadId = getOptionU32(kArgs, L"--tid", 0U);
        IoctlResult io{};
        if (!sendFixedRequestResponse(IOCTL_KSWORD_ARK_QUERY_WSL_SILO, L"IOCTL_KSWORD_ARK_QUERY_WSL_SILO", request, response, io)) return 3;
        printResponseBanner(response.version, response.queryStatus, response.processLookupStatus, io.bytesReturned);
        std::wcout << L"size=" << response.size
                   << L" fieldFlags=0x" << std::hex << response.fieldFlags
                   << L" dyn=0x" << response.dynDataCapabilityMask
                   << L" processLookup=0x" << static_cast<unsigned long>(response.processLookupStatus)
                   << L" threadLookup=0x" << static_cast<unsigned long>(response.threadLookupStatus)
                   << std::dec << L" pid=" << response.processId
                   << L" tid=" << response.threadId
                   << L" processSubsystemType=" << response.processSubsystemType
                   << L" threadSubsystemType=" << response.threadSubsystemType
                   << L" linuxPid=" << response.linuxProcessId
                   << L" linuxTid=" << response.linuxThreadId
                   << L" siloRoutinesMask=0x" << std::hex << response.siloRoutinesMask << std::dec << L"\n";
        printModuleIdentity(L"lxcore", response.lxcore);
        return 0;
    }
}

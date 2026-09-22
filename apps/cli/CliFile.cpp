#include "CliSupport.h"

namespace ksword::cli
{
    // normalizeFilePathForDriver converts Win32/UNC paths into the driver NT path
    // convention used by Ksword5.1 FileDock before sending file integrity IOCTLs.
    // Inputs: path from --path.
    // Processing: normalizes slashes and preserves already-normalized NT paths.
    // Returns: a non-empty path or throws when the input is empty.
    std::wstring normalizeFilePathForDriver(std::wstring path)
    {
        while (!path.empty() && std::iswspace(path.back()) != 0)
        {
            path.pop_back();
        }
        std::size_t first = 0U;
        while (first < path.size() && std::iswspace(path[first]) != 0)
        {
            ++first;
        }
        if (first != 0U)
        {
            path.erase(0U, first);
        }
        for (wchar_t& ch : path)
        {
            if (ch == L'/')
            {
                ch = L'\\';
            }
        }
        if (path.empty())
        {
            throw std::invalid_argument("path");
        }
        if (path.rfind(L"\\??\\", 0U) == 0U || path.rfind(L"\\Device\\", 0U) == 0U)
        {
            return path;
        }
        if (path.rfind(L"\\\\?\\", 0U) == 0U)
        {
            return L"\\??\\" + path.substr(4U);
        }
        if (path.rfind(L"\\\\", 0U) == 0U)
        {
            return L"\\??\\UNC\\" + path.substr(2U);
        }
        return L"\\??\\" + path;
    }

    // printFileIntegrityResponse renders the fixed file-integrity response.
    // Inputs: shared response packet and bytesReturned.
    // Processing: prints status, NTSTATUS, target flags and path length.
    // Returns: no value.
    void printFileIntegrityResponse(const KSWORD_ARK_SET_FILE_INTEGRITY_RESPONSE& response, DWORD bytesReturned)
    {
        printResponseBanner(response.version, response.status, response.lastStatus, bytesReturned);
        std::wcout << L"flags=0x" << std::hex << response.flags
                   << L" integrityRid=0x" << response.integrityRid
                   << L" lastStatus=0x" << static_cast<unsigned long>(response.lastStatus)
                   << std::dec << L" pathLengthChars=" << response.pathLengthChars << L"\n";
    }

    // commandFileFamily implements file and file-monitor IOCTLs.
    // Inputs: argc/argv from wmain.
    // Processing: handles delete/query and monitor control/status/drain.
    // Returns: process exit code.
    int commandFileFamily(int argc, wchar_t* argv[])
    {
        if (argc < 3) { std::wcerr << L"error: file requires a subcommand\n"; return 1; }
        const std::wstring kSub = argv[2];
        const NamedArgs kArgs = parseNamedArgs(argc, argv, 3);
        IoctlResult io{};

        if (kSub == L"delete-path")
        {
            KSWORD_ARK_DELETE_PATH_REQUEST request{};
            request.flags = getOptionU32(kArgs, L"--flags", 0U);
            const std::wstring& pathText = requireOptionText(kArgs, L"--path");
            request.pathLengthChars = boundedPathLength(pathText, KSWORD_ARK_DELETE_PATH_MAX_CHARS);
            copyWideToFixed(request.path, KSWORD_ARK_DELETE_PATH_MAX_CHARS, pathText);
            return runNoOutputIoctl(L"IOCTL_KSWORD_ARK_DELETE_PATH", IOCTL_KSWORD_ARK_DELETE_PATH, &request, sizeof(request));
        }
        if (kSub == L"query-info")
        {
            KSWORD_ARK_QUERY_FILE_INFO_REQUEST request{};
            KSWORD_ARK_QUERY_FILE_INFO_RESPONSE response{};
            request.flags = getOptionU32(kArgs, L"--flags", 0U);
            const std::wstring& pathText = requireOptionText(kArgs, L"--path");
            request.pathLengthChars = boundedPathLength(pathText, KSWORD_ARK_FILE_INFO_PATH_MAX_CHARS);
            copyWideToFixed(request.path, KSWORD_ARK_FILE_INFO_PATH_MAX_CHARS, pathText);
            if (!sendFixedRequestResponse(IOCTL_KSWORD_ARK_QUERY_FILE_INFO, L"IOCTL_KSWORD_ARK_QUERY_FILE_INFO", request, response, io)) return 3;
            printFileInfoResponse(response, io.bytesReturned);
            return 0;
        }
        if (kSub == L"set-integrity")
        {
            KSWORD_ARK_SET_FILE_INTEGRITY_REQUEST request{};
            KSWORD_ARK_SET_FILE_INTEGRITY_RESPONSE response{};
            request.size = sizeof(request);
            request.version = KSWORD_ARK_FILE_INTEGRITY_PROTOCOL_VERSION;
            request.flags = getOptionU32(kArgs, L"--flags", 0U);
            if (getOptionBool(kArgs, L"--directory"))
            {
                request.flags |= KSWORD_ARK_FILE_INTEGRITY_FLAG_DIRECTORY;
            }
            if (getOptionBool(kArgs, L"--confirm"))
            {
                request.flags |= KSWORD_ARK_FILE_INTEGRITY_FLAG_UI_CONFIRMED;
            }
            request.integrityRid = parseMandatoryIntegrityRid(kArgs);
            const std::wstring kNtPath = normalizeFilePathForDriver(requireOptionText(kArgs, L"--path"));
            request.pathLengthChars = boundedPathLength(kNtPath, KSWORD_ARK_FILE_INTEGRITY_PATH_MAX_CHARS);
            copyWideToFixed(request.path, KSWORD_ARK_FILE_INTEGRITY_PATH_MAX_CHARS, kNtPath);
            if (!sendFixedRequestResponse(
                    IOCTL_KSWORD_ARK_SET_FILE_INTEGRITY,
                    L"IOCTL_KSWORD_ARK_SET_FILE_INTEGRITY",
                    request,
                    response,
                    io,
                    GENERIC_READ | GENERIC_WRITE))
            {
                return normalizeIoctlRc(L"file set-integrity", io, 3);
            }
            printFileIntegrityResponse(response, io.bytesReturned);
            dumpWideText(L"ntPath", kNtPath);
            return 0;
        }
        if (kSub == L"fileobject")
        {
            std::wcout << L"alias: file fileobject -> file query-info\n";
            KSWORD_ARK_QUERY_FILE_INFO_REQUEST request{};
            KSWORD_ARK_QUERY_FILE_INFO_RESPONSE response{};
            request.flags = getOptionU32(kArgs, L"--flags", 0U);
            const std::wstring& pathText = requireOptionText(kArgs, L"--path");
            request.pathLengthChars = boundedPathLength(pathText, KSWORD_ARK_FILE_INFO_PATH_MAX_CHARS);
            copyWideToFixed(request.path, KSWORD_ARK_FILE_INFO_PATH_MAX_CHARS, pathText);
            if (!sendFixedRequestResponse(IOCTL_KSWORD_ARK_QUERY_FILE_INFO, L"IOCTL_KSWORD_ARK_QUERY_FILE_INFO", request, response, io)) return 3;
            printFileInfoResponse(response, io.bytesReturned);
            return 0;
        }
        if (kSub == L"minifilter")
        {
            return queryMinifilterInventory(kArgs);
        }
        if (kSub == L"section")
        {
            return commandUnsupported(L"file section", L"use section query-file-mappings --path <path> for the existing read-only Section protocol");
        }
        if (kSub == L"bitlocker")
        {
            return queryBitlockerAudit(kArgs);
        }
        if (kSub == L"storage")
        {
            return queryVolumeStackAudit(kArgs);
        }
        if (kSub == L"mountmgr")
        {
            return queryMountMgrAudit(kArgs);
        }
        if (kSub == L"filesystem")
        {
            return queryFilesystemIntegrityAudit(kArgs);
        }
        if (kSub == L"monitor-control")
        {
            KSWORD_ARK_FILE_MONITOR_CONTROL_REQUEST request{};
            request.action = requireOptionU32(kArgs, L"--action");
            request.operationMask = getOptionU32(kArgs, L"--operation-mask", 0U);
            request.processId = getOptionU32(kArgs, L"--pid", 0U);
            request.flags = getOptionU32(kArgs, L"--flags", 0U);
            return runNoOutputIoctl(L"IOCTL_KSWORD_ARK_FILE_MONITOR_CONTROL", IOCTL_KSWORD_ARK_FILE_MONITOR_CONTROL, &request, sizeof(request));
        }
        if (kSub == L"monitor-drain")
        {
            KSWORD_ARK_FILE_MONITOR_DRAIN_REQUEST request{};
            request.maxEvents = getOptionU32(kArgs, L"--max-events", KSWORD_ARK_FILE_MONITOR_RING_CAPACITY);
            request.flags = getOptionU32(kArgs, L"--flags", 0U);
            constexpr std::size_t kHeaderSize = sizeof(KSWORD_ARK_FILE_MONITOR_DRAIN_RESPONSE) - sizeof(KSWORD_ARK_FILE_MONITOR_EVENT);
            std::vector<std::uint8_t> buffer(kHugeResponseBytes, 0U);
            const int kRc = sendRawIoctl(L"IOCTL_KSWORD_ARK_FILE_MONITOR_DRAIN", IOCTL_KSWORD_ARK_FILE_MONITOR_DRAIN, &request, sizeof(request), buffer, io);
            if (kRc != 0) return kRc;
            if (io.bytesReturned < kHeaderSize) { std::wcerr << L"error: file-monitor drain response too small\n"; return 4; }
            const auto* response = reinterpret_cast<const KSWORD_ARK_FILE_MONITOR_DRAIN_RESPONSE*>(buffer.data());
            std::size_t available = 0U;
            try { available = validateVariable(io.bytesReturned, kHeaderSize, response->entrySize, sizeof(KSWORD_ARK_FILE_MONITOR_EVENT), L"file-monitor drain"); }
            catch (...) { return 4; }
            printCountHeader(response->version, response->totalQueuedBeforeDrain, response->returnedCount, response->entrySize, io.bytesReturned);
            std::wcout << L"droppedCount=" << response->droppedCount
                       << L" runtimeFlags=0x" << std::hex << response->runtimeFlags
                       << std::dec << L" ringCapacity=" << response->ringCapacity << L"\n";
            const std::size_t kParsed = responseCountLimit(response->returnedCount, available, request.maxEvents);
            for (std::size_t i = 0; i < kParsed; ++i)
            {
                const auto* entry = reinterpret_cast<const KSWORD_ARK_FILE_MONITOR_EVENT*>(buffer.data() + kHeaderSize + (i * response->entrySize));
                std::wcout << L"  [" << i << L"] op=" << entry->operationType
                           << L" major=" << entry->majorFunction
                           << L" minor=" << entry->minorFunction
                           << L" pid=" << entry->processId
                           << L" tid=" << entry->threadId
                           << L" flags=0x" << std::hex << entry->fieldFlags
                           << L" result=0x" << static_cast<unsigned long>(entry->resultStatus)
                           << std::dec << L" seq=" << entry->sequence
                           << L" path='" << fixedWide(entry->path, KSWORD_ARK_FILE_MONITOR_PATH_CHARS) << L"'";
                if ((entry->fieldFlags & KSWORD_ARK_FILE_MONITOR_FIELD_FSCTL_PRESENT) != 0UL)
                {
                    const wchar_t* fsctlText = KswordARKFileMonitorFsctlCodeToText(entry->fsControlCode);
                    std::wcout << L" fsctl=0x" << std::hex << entry->fsControlCode
                               << std::dec << L" fsInput=" << entry->fsInputBufferLength
                               << L" fsOutput=" << entry->fsOutputBufferLength
                               << L" oplock=" << (KswordARKFileMonitorFsctlIsOplockRelated(entry->fsControlCode) ? L"true" : L"false");
                    if (fsctlText != nullptr)
                    {
                        std::wcout << L" fsctlName='" << fsctlText << L"'";
                    }
                }
                std::wcout << L"\n";
            }
            return 0;
        }
        if (kSub == L"monitor-status")
        {
            KSWORD_ARK_FILE_MONITOR_STATUS_RESPONSE response{};
            if (!sendFixedNoInput(IOCTL_KSWORD_ARK_FILE_MONITOR_QUERY_STATUS, L"IOCTL_KSWORD_ARK_FILE_MONITOR_QUERY_STATUS", response, io)) return 3;
            printResponseBanner(response.version, response.runtimeFlags, response.lastErrorStatus, io.bytesReturned);
            std::wcout << L"size=" << response.size
                       << L" operationMask=0x" << std::hex << response.operationMask
                       << std::dec << L" pidFilter=" << response.processIdFilter
                       << L" ringCapacity=" << response.ringCapacity
                       << L" queued=" << response.queuedCount
                       << L" dropped=" << response.droppedCount
                       << L" sequence=" << response.sequence
                       << L" registerStatus=0x" << std::hex << static_cast<unsigned long>(response.registerStatus)
                       << L" startStatus=0x" << static_cast<unsigned long>(response.startStatus)
                       << std::dec << L"\n";
            return 0;
        }
        std::wcerr << L"error: unknown file subcommand '" << kSub << L"'\n";
        return 1;
    }
}

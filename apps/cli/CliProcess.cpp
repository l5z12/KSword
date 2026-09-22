#include "CliSupport.h"

namespace ksword::cli
{
    // printProcessEnumRow renders a process enumeration entry.
    // Inputs: protocol row from KSWORD_ARK_PROCESS_ENTRY.
    // Processing: prints stable identifiers and optional image path.
    // Returns: no value.
    void printProcessEnumRow(const KSWORD_ARK_PROCESS_ENTRY& entry)
    {
        std::wcout << L"  pid=" << entry.processId
                   << L" ppid=" << entry.parentProcessId
                   << L" flags=0x" << std::hex << entry.flags
                   << L" fieldFlags=0x" << entry.fieldFlags
                   << std::dec << L" r0Status=" << entry.r0Status
                   << L" session=" << entry.sessionId
                   << L" objectTable=" << hex64(entry.objectTableAddress)
                   << L" section=" << hex64(entry.sectionObjectAddress)
                   << L" image='" << fixedAnsi(entry.imageName, sizeof(entry.imageName)).c_str() << L"'";
        const std::wstring kImagePath = fixedUtf16(entry.imagePath, KSWORD_ARK_PROCESS_IMAGE_PATH_CHARS);
        if (!kImagePath.empty()) std::wcout << L" path='" << kImagePath << L"'";
        std::wcout << L"\n";
    }

    // parseMandatoryIntegrityRid parses --rid or --level into a SID mandatory RID.
    // Inputs: named CLI args; accepted levels mirror Ksword5.1 UI presets.
    // Processing: --rid wins over --level; named levels map to SECURITY_MANDATORY_*.
    // Returns: RID value for R0 process/file integrity IOCTLs.
    std::uint32_t parseMandatoryIntegrityRid(const NamedArgs& args)
    {
        const std::wstring* ridText = getOptionText(args, L"--rid");
        if (ridText != nullptr)
        {
            return parseU32(ridText->c_str(), "integrity rid");
        }

        const std::wstring kLevel = lowerWide(requireOptionText(args, L"--level"));
        if (kLevel == L"untrusted") return SECURITY_MANDATORY_UNTRUSTED_RID;
        if (kLevel == L"low") return SECURITY_MANDATORY_LOW_RID;
        if (kLevel == L"medium") return SECURITY_MANDATORY_MEDIUM_RID;
        if (kLevel == L"medium-plus" || kLevel == L"mediumplus") return SECURITY_MANDATORY_MEDIUM_PLUS_RID;
        if (kLevel == L"high") return SECURITY_MANDATORY_HIGH_RID;
        if (kLevel == L"system") return SECURITY_MANDATORY_SYSTEM_RID;
        if (kLevel == L"protected") return SECURITY_MANDATORY_PROTECTED_PROCESS_RID;
        throw std::invalid_argument("integrity level");
    }

    // printProcessIntegrityResponse renders the fixed process-integrity response.
    // Inputs: shared response packet and DeviceIoControl byte count.
    // Processing: prints status, NTSTATUS and target RID.
    // Returns: no value.
    void printProcessIntegrityResponse(const KSWORD_ARK_SET_PROCESS_INTEGRITY_RESPONSE& response, DWORD bytesReturned)
    {
        printResponseBanner(response.version, response.status, response.lastStatus, bytesReturned);
        std::wcout << L"pid=" << response.processId
                   << L" integrityRid=0x" << std::hex << response.integrityRid
                   << L" lastStatus=0x" << static_cast<unsigned long>(response.lastStatus)
                   << std::dec << L"\n";
    }

    // buildInjectRequestBuffer creates a METHOD_BUFFERED process injection packet.
    // Inputs: parsed args, inject type and payload bytes/entrypoint values.
    // Processing: allocates exactly header+payload bytes and fills the shared
    // protocol fields.
    // Returns: byte vector ready for IOCTL_KSWORD_ARK_INJECT_PROCESS.
    std::vector<std::uint8_t> buildInjectRequestBuffer(
        const NamedArgs& args,
        std::uint32_t injectType,
        const std::vector<std::uint8_t>& payload,
        std::uint64_t entryPointAddress,
        std::uint64_t parameterAddress,
        unsigned long defaultFlags)
    {
        if (payload.empty() || payload.size() > KSWORD_ARK_PROCESS_INJECT_MAX_PAYLOAD_BYTES)
        {
            throw std::out_of_range("inject payload");
        }
        const std::size_t kHeaderSize = sizeof(KSWORD_ARK_INJECT_PROCESS_REQUEST) - sizeof(unsigned char);
        std::vector<std::uint8_t> buffer(kHeaderSize + payload.size(), 0U);
        auto* request = reinterpret_cast<KSWORD_ARK_INJECT_PROCESS_REQUEST*>(buffer.data());
        request->version = KSWORD_ARK_PROCESS_INJECT_PROTOCOL_VERSION;
        request->processId = requireOptionU32(args, L"--pid");
        request->injectType = injectType;
        request->flags = getOptionU32(args, L"--flags", defaultFlags);
        if (getOptionBool(args, L"--confirm"))
        {
            request->flags |= KSWORD_ARK_PROCESS_INJECT_FLAG_UI_CONFIRMED;
        }
        if (getOptionBool(args, L"--wait-thread"))
        {
            request->flags |= KSWORD_ARK_PROCESS_INJECT_FLAG_WAIT_THREAD;
        }
        request->payloadBytes = static_cast<unsigned long>(payload.size());
        request->entryPointAddress = entryPointAddress;
        request->parameterAddress = parameterAddress;
        std::memcpy(request->payload, payload.data(), payload.size());
        return buffer;
    }

    // requireConfirmOption gates high-risk process injection and HWID control paths.
    // Inputs: parsed args and a command label.
    // Processing: throws when --confirm is absent.
    // Returns: no value when confirmation is present.
    void requireConfirmOption(const NamedArgs& args, const char* label)
    {
        if (!getOptionBool(args, L"--confirm"))
        {
            throw std::invalid_argument(label);
        }
    }

    // printInjectResponse renders the fixed process injection response.
    // Inputs: response packet and bytesReturned.
    // Processing: prints remote allocation and thread entry diagnostics.
    // Returns: no value.
    void printInjectResponse(const KSWORD_ARK_INJECT_PROCESS_RESPONSE& response, DWORD bytesReturned)
    {
        printResponseBanner(response.version, response.status, response.lastStatus, bytesReturned);
        std::wcout << L"pid=" << response.processId
                   << L" type=" << response.injectType
                   << L" flags=0x" << std::hex << response.flags
                   << L" entry=" << hex64(response.entryPointAddress)
                   << L" parameter=" << hex64(response.parameterAddress)
                   << L" remoteBase=" << hex64(response.remoteBaseAddress)
                   << L" remoteSize=" << hex64(response.remoteRegionSize)
                   << L" lastStatus=0x" << static_cast<unsigned long>(response.lastStatus)
                   << L" waitStatus=0x" << static_cast<unsigned long>(response.waitStatus)
                   << std::dec << L" bytesWritten=" << response.bytesWritten << L"\n";
    }

    // buildDllInjectPayload builds the UTF-16 LoadLibraryW payload.
    // Inputs: --dll path string.
    // Processing: includes the trailing NUL exactly like ArkDriverClient.
    // Returns: raw byte payload for R0 remote write.
    std::vector<std::uint8_t> buildDllInjectPayload(const std::wstring& dllPath)
    {
        if (dllPath.empty())
        {
            throw std::invalid_argument("dll path");
        }
        const std::size_t kPayloadBytes = (dllPath.size() + 1U) * sizeof(wchar_t);
        if (kPayloadBytes > KSWORD_ARK_PROCESS_INJECT_MAX_PAYLOAD_BYTES)
        {
            throw std::out_of_range("dll path payload");
        }
        std::vector<std::uint8_t> payload(kPayloadBytes, 0U);
        std::memcpy(payload.data(), dllPath.c_str(), kPayloadBytes);
        return payload;
    }

    // resolveLoadLibraryW returns the current process LoadLibraryW address used by
    // the existing ArkDriverClient DLL-injection wrapper.
    // Inputs: none.
    // Processing: resolves kernel32!LoadLibraryW in this process.
    // Returns: function address as an integer or throws on failure.
    std::uint64_t resolveLoadLibraryW()
    {
        HMODULE kernel32 = ::GetModuleHandleW(L"kernel32.dll");
        if (kernel32 == nullptr)
        {
            throw std::runtime_error("kernel32.dll");
        }
        FARPROC loadLibrary = ::GetProcAddress(kernel32, "LoadLibraryW");
        if (loadLibrary == nullptr)
        {
            throw std::runtime_error("LoadLibraryW");
        }
        return static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(loadLibrary));
    }

    // commandProcessFamily implements all registered process IOCTLs.
    // Inputs: argc/argv from wmain.
    // Processing: builds fixed or variable protocol requests from named args.
    // Returns: process exit code.
    int commandProcessFamily(int argc, wchar_t* argv[])
    {
        if (argc < 3) { std::wcerr << L"error: process requires a subcommand\n"; return 1; }
        const std::wstring kSub = argv[2];
        const NamedArgs kArgs = parseNamedArgs(argc, argv, 3);
        IoctlResult io{};

        if (kSub == L"terminate")
        {
            KSWORD_ARK_TERMINATE_PROCESS_REQUEST request{};
            request.processId = requireOptionU32(kArgs, L"--pid");
            request.exitStatus = static_cast<long>(getOptionU32(kArgs, L"--exit-status", 0xC000013AUL));
            return runNoOutputIoctl(L"IOCTL_KSWORD_ARK_TERMINATE_PROCESS", IOCTL_KSWORD_ARK_TERMINATE_PROCESS, &request, sizeof(request));
        }
        if (kSub == L"suspend")
        {
            KSWORD_ARK_SUSPEND_PROCESS_REQUEST request{};
            request.processId = requireOptionU32(kArgs, L"--pid");
            return runNoOutputIoctl(L"IOCTL_KSWORD_ARK_SUSPEND_PROCESS", IOCTL_KSWORD_ARK_SUSPEND_PROCESS, &request, sizeof(request));
        }
        if (kSub == L"resume")
        {
            KSWORD_ARK_RESUME_PROCESS_REQUEST request{};
            request.processId = requireOptionU32(kArgs, L"--pid");
            return runNoOutputIoctl(L"IOCTL_KSWORD_ARK_RESUME_PROCESS", IOCTL_KSWORD_ARK_RESUME_PROCESS, &request, sizeof(request));
        }
        if (kSub == L"set-ppl")
        {
            KSWORD_ARK_SET_PPL_LEVEL_REQUEST request{};
            request.processId = requireOptionU32(kArgs, L"--pid");
            request.protectionLevel = static_cast<unsigned char>(requireOptionU32(kArgs, L"--level") & 0xFFU);
            return runNoOutputIoctl(L"IOCTL_KSWORD_ARK_SET_PPL_LEVEL", IOCTL_KSWORD_ARK_SET_PPL_LEVEL, &request, sizeof(request));
        }
        if (kSub == L"set-integrity")
        {
            KSWORD_ARK_SET_PROCESS_INTEGRITY_REQUEST request{};
            KSWORD_ARK_SET_PROCESS_INTEGRITY_RESPONSE response{};
            request.size = sizeof(request);
            request.version = KSWORD_ARK_PROCESS_INTEGRITY_PROTOCOL_VERSION;
            request.processId = requireOptionU32(kArgs, L"--pid");
            request.integrityRid = parseMandatoryIntegrityRid(kArgs);
            request.flags = getOptionU32(kArgs, L"--flags", 0U);
            if (getOptionBool(kArgs, L"--confirm"))
            {
                request.flags |= KSWORD_ARK_PROCESS_INTEGRITY_FLAG_UI_CONFIRMED;
            }
            if (!sendFixedRequestResponse(
                    IOCTL_KSWORD_ARK_SET_PROCESS_INTEGRITY,
                    L"IOCTL_KSWORD_ARK_SET_PROCESS_INTEGRITY",
                    request,
                    response,
                    io,
                    GENERIC_READ | GENERIC_WRITE))
            {
                return normalizeIoctlRc(L"process set-integrity", io, 3);
            }
            printProcessIntegrityResponse(response, io.bytesReturned);
            return 0;
        }
        if (kSub == L"inject-dll")
        {
            requireConfirmOption(kArgs, "process inject-dll requires --confirm");
            KSWORD_ARK_INJECT_PROCESS_RESPONSE response{};
            const std::wstring& dllPath = requireOptionText(kArgs, L"--dll");
            std::vector<std::uint8_t> payload = buildDllInjectPayload(dllPath);
            std::vector<std::uint8_t> request = buildInjectRequestBuffer(
                kArgs,
                KSWORD_ARK_PROCESS_INJECT_TYPE_DLL_PATH,
                payload,
                resolveLoadLibraryW(),
                0ULL,
                KSWORD_ARK_PROCESS_INJECT_FLAG_WAIT_THREAD);
            std::vector<std::uint8_t> output(sizeof(response), 0U);
            const int kRc = sendRawIoctl(
                L"IOCTL_KSWORD_ARK_INJECT_PROCESS",
                IOCTL_KSWORD_ARK_INJECT_PROCESS,
                request.data(),
                checkedDwordSize(request.size()),
                output,
                io,
                GENERIC_READ | GENERIC_WRITE);
            if (kRc != 0)
            {
                return normalizeIoctlRc(L"process inject-dll", io, kRc);
            }
            if (io.bytesReturned < sizeof(response))
            {
                std::wcerr << L"error: process inject-dll response too small: " << io.bytesReturned << L" bytes\n";
                return 4;
            }
            std::memcpy(&response, output.data(), sizeof(response));
            printInjectResponse(response, io.bytesReturned);
            return 0;
        }
        if (kSub == L"inject-shellcode")
        {
            requireConfirmOption(kArgs, "process inject-shellcode requires --confirm");
            KSWORD_ARK_INJECT_PROCESS_RESPONSE response{};
            std::vector<std::uint8_t> payload = readFileBytes(requireOptionText(kArgs, L"--blob"), KSWORD_ARK_PROCESS_INJECT_MAX_PAYLOAD_BYTES);
            std::vector<std::uint8_t> request = buildInjectRequestBuffer(
                kArgs,
                KSWORD_ARK_PROCESS_INJECT_TYPE_SHELLCODE,
                payload,
                0ULL,
                0ULL,
                0UL);
            std::vector<std::uint8_t> output(sizeof(response), 0U);
            const int kRc = sendRawIoctl(
                L"IOCTL_KSWORD_ARK_INJECT_PROCESS",
                IOCTL_KSWORD_ARK_INJECT_PROCESS,
                request.data(),
                checkedDwordSize(request.size()),
                output,
                io,
                GENERIC_READ | GENERIC_WRITE);
            if (kRc != 0)
            {
                return normalizeIoctlRc(L"process inject-shellcode", io, kRc);
            }
            if (io.bytesReturned < sizeof(response))
            {
                std::wcerr << L"error: process inject-shellcode response too small: " << io.bytesReturned << L" bytes\n";
                return 4;
            }
            std::memcpy(&response, output.data(), sizeof(response));
            printInjectResponse(response, io.bytesReturned);
            return 0;
        }
        if (kSub == L"enum")
        {
            KSWORD_ARK_ENUM_PROCESS_REQUEST request{};
            request.flags = getOptionU32(kArgs, L"--flags", 0U);
            request.startPid = getOptionU32(kArgs, L"--start-pid", 0U);
            request.endPid = getOptionU32(kArgs, L"--end-pid", 0U);
            const std::uint32_t kLimit = getOptionU32(kArgs, L"--limit", 128U);
            std::vector<std::uint8_t> buffer(kLargeResponseBytes, 0U);
            const int kRc = sendRawIoctl(L"IOCTL_KSWORD_ARK_ENUM_PROCESS", IOCTL_KSWORD_ARK_ENUM_PROCESS, &request, sizeof(request), buffer, io);
            if (kRc != 0) return kRc;
            constexpr std::size_t kHeaderSize = sizeof(KSWORD_ARK_ENUM_PROCESS_RESPONSE) - sizeof(KSWORD_ARK_PROCESS_ENTRY);
            if (io.bytesReturned < kHeaderSize) { std::wcerr << L"error: process enum response too small\n"; return 4; }
            const auto* response = reinterpret_cast<const KSWORD_ARK_ENUM_PROCESS_RESPONSE*>(buffer.data());
            std::size_t available = 0U;
            try { available = validateVariable(io.bytesReturned, kHeaderSize, response->entrySize, sizeof(KSWORD_ARK_PROCESS_ENTRY), L"process enum"); }
            catch (...) { return 4; }
            printCountHeader(response->version, response->totalCount, response->returnedCount, response->entrySize, io.bytesReturned);
            const std::size_t kParsed = responseCountLimit(response->returnedCount, available, kLimit);
            for (std::size_t i = 0; i < kParsed; ++i)
            {
                const auto* entry = reinterpret_cast<const KSWORD_ARK_PROCESS_ENTRY*>(buffer.data() + kHeaderSize + (i * response->entrySize));
                printProcessEnumRow(*entry);
            }
            return 0;
        }
        if (kSub == L"set-visibility")
        {
            KSWORD_ARK_SET_PROCESS_VISIBILITY_REQUEST request{};
            KSWORD_ARK_SET_PROCESS_VISIBILITY_RESPONSE response{};
            request.processId = getOptionU32(kArgs, L"--pid", 0U);
            request.action = requireOptionU32(kArgs, L"--action");
            request.flags = getOptionU32(kArgs, L"--flags", 0U);
            if (!sendFixedRequestResponse(IOCTL_KSWORD_ARK_SET_PROCESS_VISIBILITY, L"IOCTL_KSWORD_ARK_SET_PROCESS_VISIBILITY", request, response, io)) return 3;
            printResponseBanner(response.version, response.status, response.lastStatus, io.bytesReturned);
            std::wcout << L"pid=" << response.processId
                       << L" action=" << request.action
                       << L" requestFlags=0x" << std::hex << request.flags
                       << std::dec << L" hiddenCount=" << response.hiddenCount << L"\n";
            return 0;
        }
        if (kSub == L"set-special-flags")
        {
            KSWORD_ARK_SET_PROCESS_SPECIAL_FLAGS_REQUEST request{};
            KSWORD_ARK_SET_PROCESS_SPECIAL_FLAGS_RESPONSE response{};
            request.version = KSWORD_ARK_ENUM_PROCESS_PROTOCOL_VERSION;
            request.processId = requireOptionU32(kArgs, L"--pid");
            request.action = requireOptionU32(kArgs, L"--action");
            request.flags = getOptionU32(kArgs, L"--flags", 0U);
            if (!sendFixedRequestResponse(IOCTL_KSWORD_ARK_SET_PROCESS_SPECIAL_FLAGS, L"IOCTL_KSWORD_ARK_SET_PROCESS_SPECIAL_FLAGS", request, response, io)) return 3;
            printResponseBanner(response.version, response.status, response.lastStatus, io.bytesReturned);
            std::wcout << L"pid=" << response.processId << L" action=" << response.action
                       << L" appliedFlags=0x" << std::hex << response.appliedFlags
                       << std::dec << L" touchedThreadCount=" << response.touchedThreadCount << L"\n";
            return 0;
        }
        if (kSub == L"dkom")
        {
            KSWORD_ARK_DKOM_PROCESS_REQUEST request{};
            KSWORD_ARK_DKOM_PROCESS_RESPONSE response{};
            request.version = KSWORD_ARK_ENUM_PROCESS_PROTOCOL_VERSION;
            request.processId = requireOptionU32(kArgs, L"--pid");
            request.action = getOptionU32(kArgs, L"--action", KSWORD_ARK_PROCESS_DKOM_ACTION_REMOVE_FROM_PSP_CID_TABLE);
            request.flags = getOptionU32(kArgs, L"--flags", 0U);
            if (!sendFixedRequestResponse(IOCTL_KSWORD_ARK_DKOM_PROCESS, L"IOCTL_KSWORD_ARK_DKOM_PROCESS", request, response, io)) return 3;
            printResponseBanner(response.version, response.status, response.lastStatus, io.bytesReturned);
            std::wcout << L"pid=" << response.processId << L" action=" << response.action
                       << L" removedEntries=" << response.removedEntries
                       << L" pspCidTable=" << hex64(response.pspCidTableAddress)
                       << L" processObject=" << hex64(response.processObjectAddress) << L"\n";
            return 0;
        }
        if (kSub == L"crossview")
        {
            KSWORD_ARK_PROCESS_CROSSVIEW_REQUEST request{};
            request.version = KSWORD_ARK_CROSSVIEW_PROTOCOL_VERSION;
            request.flags = getOptionU32(kArgs, L"--flags", KSWORD_ARK_PROCESS_CROSSVIEW_FLAG_INCLUDE_ALL);
            request.startPid = getOptionU32(kArgs, L"--start-pid", 0U);
            request.endPid = getOptionU32(kArgs, L"--end-pid", 0U);
            request.maxNodes = getOptionU32(kArgs, L"--max-nodes", KSWORD_ARK_CROSSVIEW_DEFAULT_MAX_NODES);
            const std::uint32_t kLimit = getOptionU32(kArgs, L"--limit", 128U);
            std::vector<std::uint8_t> buffer(kHugeResponseBytes, 0U);
            const int kRc = sendRawIoctl(L"IOCTL_KSWORD_ARK_QUERY_PROCESS_CROSSVIEW", IOCTL_KSWORD_ARK_QUERY_PROCESS_CROSSVIEW, &request, sizeof(request), buffer, io);
            if (kRc != 0) return normalizeIoctlRc(L"process crossview", io, kRc);
            constexpr std::size_t kHeaderSize = sizeof(KSWORD_ARK_PROCESS_CROSSVIEW_RESPONSE) - sizeof(KSWORD_ARK_PROCESS_CROSSVIEW_ROW);
            if (io.bytesReturned < kHeaderSize) { std::wcerr << L"error: process crossview response too small\n"; return 4; }
            const auto* response = reinterpret_cast<const KSWORD_ARK_PROCESS_CROSSVIEW_RESPONSE*>(buffer.data());
            std::size_t available = 0U;
            try { available = validateVariable(io.bytesReturned, kHeaderSize, response->entrySize, sizeof(KSWORD_ARK_PROCESS_CROSSVIEW_ROW), L"process crossview"); }
            catch (...) { return 4; }
            printResponseBanner(response->version, response->status, response->lastStatus, io.bytesReturned);
            printCountHeader(response->version, response->totalCount, response->returnedCount, response->entrySize, io.bytesReturned);
            std::wcout << L"dynMask=0x" << std::hex << response->dynDataCapabilityMask
                       << L" missingMask=0x" << response->missingCapabilityMask << std::dec << L"\n";
            const std::size_t kParsed = responseCountLimit(response->returnedCount, available, kLimit);
            for (std::size_t i = 0; i < kParsed; ++i)
            {
                const auto* row = reinterpret_cast<const KSWORD_ARK_PROCESS_CROSSVIEW_ROW*>(buffer.data() + kHeaderSize + (i * response->entrySize));
                std::wcout << L"  [" << i << L"] pid=" << row->processId
                           << L" ppid=" << row->parentProcessId
                           << L" source=0x" << std::hex << row->sourceMask
                           << L" anomaly=0x" << row->anomalyFlags
                           << L" object=" << hex64(row->objectAddress)
                           << L" start=" << hex64(row->startAddress)
                           << std::dec << L" confidence=" << row->confidence
                           << L" image='" << fixedAnsi(row->imageName, sizeof(row->imageName)).c_str()
                           << L"' detail='" << fixedAnsi(row->detail, sizeof(row->detail)).c_str() << L"'\n";
            }
            return 0;
        }
        if (kSub == L"detail")
        {
            // process detail:
            // - Inputs: --pid selects the process and --flags selects fixed
            //   read-only EPROCESS detail groups.
            // - Processing: sends the fixed detail request through the shared
            //   protocol and prints every returned identity/object/global field.
            // - Returns: CLI status from the transport/protocol parser.
            KSWORD_ARK_PROCESS_DETAIL_REQUEST request{};
            KSWORD_ARK_PROCESS_DETAIL_RESPONSE response{};
            request.version = KSWORD_ARK_RUNTIME_DETAIL_PROTOCOL_VERSION;
            request.flags = getOptionU32(kArgs, L"--flags", KSWORD_ARK_PROCESS_DETAIL_FLAG_INCLUDE_ALL);
            request.processId = requireOptionU32(kArgs, L"--pid");
            if (!sendFixedRequestResponse(IOCTL_KSWORD_ARK_QUERY_PROCESS_DETAIL, L"IOCTL_KSWORD_ARK_QUERY_PROCESS_DETAIL", request, response, io))
            {
                return normalizeIoctlRc(L"process detail", io, 3);
            }
            printProcessDetail(response, io.bytesReturned);
            return 0;
        }
        if (kSub == L"runtime-fields")
        {
            // process runtime-fields:
            // - Inputs: --pid and --items id:offset:size[:flags] rows.
            // - Processing: builds the variable METHOD_BUFFERED input packet
            //   and receives a bounded array of field sample rows.
            // - Returns: zero after printing rows, non-zero on parse/transport error.
            std::vector<std::uint8_t> input = buildProcessRuntimeFieldInput(kArgs);
            std::vector<std::uint8_t> buffer(kSmallResponseBytes, 0U);
            const int kRc = sendRawIoctl(
                L"IOCTL_KSWORD_ARK_QUERY_PROCESS_RUNTIME_FIELDS",
                IOCTL_KSWORD_ARK_QUERY_PROCESS_RUNTIME_FIELDS,
                input.data(),
                checkedDwordSize(input.size()),
                buffer,
                io);
            if (kRc != 0)
            {
                return normalizeIoctlRc(L"process runtime-fields", io, kRc);
            }
            return printRuntimeFieldSampleRows(buffer, io, kArgs, L"process runtime-fields");
        }
        std::wcerr << L"error: unknown process subcommand '" << kSub << L"'\n";
        return 1;
    }
}

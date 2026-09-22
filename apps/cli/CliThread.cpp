#include "CliSupport.h"

namespace ksword::cli
{
    // commandThreadFamily implements thread enumeration and cross-view IOCTLs.
    // Inputs: argc/argv from wmain.
    // Processing: issues variable response queries and prints bounded rows.
    // Returns: process exit code.
    int commandThreadFamily(int argc, wchar_t* argv[])
    {
        if (argc < 3) { std::wcerr << L"error: thread requires a subcommand\n"; return 1; }
        const std::wstring kSub = argv[2];
        const NamedArgs kArgs = parseNamedArgs(argc, argv, 3);
        IoctlResult io{};
        if (kSub == L"enum")
        {
            KSWORD_ARK_ENUM_THREAD_REQUEST request{};
            request.flags = getOptionU32(kArgs, L"--flags", KSWORD_ARK_ENUM_THREAD_FLAG_INCLUDE_ALL);
            request.processId = getOptionU32(kArgs, L"--pid", 0U);
            std::vector<std::uint8_t> buffer(kLargeResponseBytes, 0U);
            const int kRc = sendRawIoctl(L"IOCTL_KSWORD_ARK_ENUM_THREAD", IOCTL_KSWORD_ARK_ENUM_THREAD, &request, sizeof(request), buffer, io);
            if (kRc != 0) return kRc;
            constexpr std::size_t kHeaderSize = sizeof(KSWORD_ARK_ENUM_THREAD_RESPONSE) - sizeof(KSWORD_ARK_THREAD_ENTRY);
            const auto* response = reinterpret_cast<const KSWORD_ARK_ENUM_THREAD_RESPONSE*>(buffer.data());
            std::size_t available = 0U;
            try { available = validateVariable(io.bytesReturned, kHeaderSize, response->entrySize, sizeof(KSWORD_ARK_THREAD_ENTRY), L"thread enum"); }
            catch (...) { return 4; }
            printCountHeader(response->version, response->totalCount, response->returnedCount, response->entrySize, io.bytesReturned);
            const std::size_t kParsed = responseCountLimit(response->returnedCount, available, getOptionU32(kArgs, L"--limit", 128U));
            for (std::size_t i = 0; i < kParsed; ++i)
            {
                const auto* entry = reinterpret_cast<const KSWORD_ARK_THREAD_ENTRY*>(buffer.data() + kHeaderSize + (i * response->entrySize));
                printSimpleThreadEntry(*entry);
            }
            return 0;
        }
        if (kSub == L"crossview")
        {
            KSWORD_ARK_THREAD_CROSSVIEW_REQUEST request{};
            request.version = KSWORD_ARK_CROSSVIEW_PROTOCOL_VERSION;
            request.flags = getOptionU32(kArgs, L"--flags", KSWORD_ARK_THREAD_CROSSVIEW_FLAG_INCLUDE_ALL);
            request.processId = getOptionU32(kArgs, L"--pid", 0U);
            request.startTid = getOptionU32(kArgs, L"--start-tid", 0U);
            request.endTid = getOptionU32(kArgs, L"--end-tid", 0U);
            request.maxNodes = getOptionU32(kArgs, L"--max-nodes", KSWORD_ARK_CROSSVIEW_DEFAULT_MAX_NODES);
            std::vector<std::uint8_t> buffer(kHugeResponseBytes, 0U);
            const int kRc = sendRawIoctl(L"IOCTL_KSWORD_ARK_QUERY_THREAD_CROSSVIEW", IOCTL_KSWORD_ARK_QUERY_THREAD_CROSSVIEW, &request, sizeof(request), buffer, io);
            if (kRc != 0) return normalizeIoctlRc(L"thread crossview", io, kRc);
            constexpr std::size_t kHeaderSize = sizeof(KSWORD_ARK_THREAD_CROSSVIEW_RESPONSE) - sizeof(KSWORD_ARK_THREAD_CROSSVIEW_ROW);
            const auto* response = reinterpret_cast<const KSWORD_ARK_THREAD_CROSSVIEW_RESPONSE*>(buffer.data());
            std::size_t available = 0U;
            try { available = validateVariable(io.bytesReturned, kHeaderSize, response->entrySize, sizeof(KSWORD_ARK_THREAD_CROSSVIEW_ROW), L"thread crossview"); }
            catch (...) { return 4; }
            printResponseBanner(response->version, response->status, response->lastStatus, io.bytesReturned);
            printCountHeader(response->version, response->totalCount, response->returnedCount, response->entrySize, io.bytesReturned);
            std::wcout << L"dynDataCapabilityMask=0x" << std::hex << response->dynDataCapabilityMask
                       << L" missingCapabilityMask=0x" << response->missingCapabilityMask << std::dec << L"\n";
            const std::size_t kParsed = responseCountLimit(response->returnedCount, available, getOptionU32(kArgs, L"--limit", 128U));
            for (std::size_t i = 0; i < kParsed; ++i)
            {
                const auto* row = reinterpret_cast<const KSWORD_ARK_THREAD_CROSSVIEW_ROW*>(buffer.data() + kHeaderSize + (i * response->entrySize));
                std::wcout << L"  [" << i << L"] pid=" << row->processId
                           << L" tid=" << row->threadId
                           << L" object=" << hex64(row->objectAddress)
                           << L" processObject=" << hex64(row->processObjectAddress)
                           << L" start=" << hex64(row->startAddress)
                           << L" source=0x" << std::hex << row->sourceMask
                           << L" anomaly=0x" << row->anomalyFlags
                           << L" last=0x" << static_cast<unsigned long>(row->lastStatus)
                           << std::dec << L" confidence=" << row->confidence
                           << L" image='" << fixedAnsiWide(row->imageName, sizeof(row->imageName))
                           << L"' detail='" << fixedAnsiWide(row->detail, KSWORD_ARK_CROSSVIEW_DETAIL_CHARS) << L"'\n";
            }
            return 0;
        }
        if (kSub == L"detail")
        {
            // thread detail:
            // - Inputs: --tid is required; --pid narrows the expected owner
            //   process when the caller already has context.
            // - Processing: requests fixed ETHREAD/KTHREAD runtime detail and
            //   prints object, start, stack, I/O and global evidence fields.
            // - Returns: normalized CLI status.
            KSWORD_ARK_THREAD_DETAIL_REQUEST request{};
            KSWORD_ARK_THREAD_DETAIL_RESPONSE response{};
            request.version = KSWORD_ARK_RUNTIME_DETAIL_PROTOCOL_VERSION;
            request.flags = getOptionU32(kArgs, L"--flags", KSWORD_ARK_THREAD_DETAIL_FLAG_INCLUDE_ALL);
            request.threadId = requireOptionU32(kArgs, L"--tid");
            request.processId = getOptionU32(kArgs, L"--pid", 0U);
            if (!sendFixedRequestResponse(IOCTL_KSWORD_ARK_QUERY_THREAD_DETAIL, L"IOCTL_KSWORD_ARK_QUERY_THREAD_DETAIL", request, response, io))
            {
                return normalizeIoctlRc(L"thread detail", io, 3);
            }
            printThreadDetail(response, io.bytesReturned);
            return 0;
        }
        if (kSub == L"runtime-fields")
        {
            // thread runtime-fields:
            // - Inputs: --tid, optional --pid, and --items sample descriptors.
            // - Processing: builds the variable ETHREAD/KTHREAD sample request
            //   and prints the bounded response rows.
            // - Returns: zero on printed rows, non-zero on parse/transport error.
            std::vector<std::uint8_t> input = buildThreadRuntimeFieldInput(kArgs);
            std::vector<std::uint8_t> buffer(kSmallResponseBytes, 0U);
            const int kRc = sendRawIoctl(
                L"IOCTL_KSWORD_ARK_QUERY_THREAD_RUNTIME_FIELDS",
                IOCTL_KSWORD_ARK_QUERY_THREAD_RUNTIME_FIELDS,
                input.data(),
                checkedDwordSize(input.size()),
                buffer,
                io);
            if (kRc != 0)
            {
                return normalizeIoctlRc(L"thread runtime-fields", io, kRc);
            }
            return printRuntimeFieldSampleRows(buffer, io, kArgs, L"thread runtime-fields");
        }
        std::wcerr << L"error: unknown thread subcommand '" << kSub << L"'\n";
        return 1;
    }
}

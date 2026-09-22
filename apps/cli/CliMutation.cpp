#include "CliSupport.h"

namespace ksword::cli
{
    // commandMutationFamily implements prepare/commit/rollback and audit queries.
    // Inputs: argc/argv from wmain.
    // Processing: loads hex or file blobs and renders audit rows.
    // Returns: process exit code.
    int commandMutationFamily(int argc, wchar_t* argv[])
    {
        if (argc < 3) { std::wcerr << L"error: mutation requires a subcommand\n"; return 1; }
        const std::wstring kSub = argv[2];
        const NamedArgs kArgs = parseNamedArgs(argc, argv, 3);
        IoctlResult io{};
        if (kSub == L"prepare")
        {
            std::vector<std::uint8_t> afterBytes = loadBytesFromHexOrFile(kArgs, L"--after-hex", L"--after-file", KSWORD_ARK_MUTATION_MAX_BYTES, true);
            std::vector<std::uint8_t> beforeBytes = loadBytesFromHexOrFile(kArgs, L"--before-hex", L"--before-file", KSWORD_ARK_MUTATION_MAX_BYTES, false);
            KSWORD_ARK_MUTATION_PREPARE_REQUEST request{};
            KSWORD_ARK_MUTATION_RESPONSE response{};
            request.size = sizeof(request);
            request.version = KSWORD_ARK_MUTATION_PROTOCOL_VERSION;
            request.flags = getOptionU32(kArgs, L"--flags", 0U);
            request.targetKind = requireOptionU32(kArgs, L"--target-kind");
            request.processId = getOptionU32(kArgs, L"--pid", 0U);
            request.bytes = static_cast<unsigned long>(afterBytes.size());
            request.targetAddress = getOptionU64(kArgs, L"--address", 0ULL);
            request.targetContext = getOptionU64(kArgs, L"--context", 0ULL);
            copyBytesToFixed(request.afterBytes, KSWORD_ARK_MUTATION_MAX_BYTES, afterBytes);
            copyBytesToFixed(request.expectedBeforeBytes, KSWORD_ARK_MUTATION_MAX_BYTES, beforeBytes);
            if (!sendFixedRequestResponse(IOCTL_KSWORD_ARK_MUTATION_PREPARE, L"IOCTL_KSWORD_ARK_MUTATION_PREPARE", request, response, io, GENERIC_READ | GENERIC_WRITE)) return 3;
            printResponseBanner(response.version, response.status, response.lastStatus, io.bytesReturned);
            std::wcout << L"size=" << response.size
                       << L" targetKind=" << response.targetKind
                       << L" pid=" << response.processId
                       << L" bytes=" << response.bytes
                       << L" riskFlags=0x" << std::hex << response.riskFlags
                       << L" transactionId=" << response.transactionId
                       << L" targetAddress=" << hex64(response.targetAddress)
                       << L" targetContext=" << hex64(response.targetContext)
                       << L" beforeHash=" << hex64(response.beforeHash)
                       << L" afterHash=" << hex64(response.afterHash)
                       << std::dec << L" timestampTick=" << response.timestampTick << L"\n";
            printBytesInline(L"beforeBytes", response.beforeBytes, response.bytes);
            printBytesInline(L"afterBytes", response.afterBytes, response.bytes);
            return 0;
        }
        if (kSub == L"commit" || kSub == L"rollback")
        {
            KSWORD_ARK_MUTATION_TRANSACTION_REQUEST request{};
            KSWORD_ARK_MUTATION_RESPONSE response{};
            request.size = sizeof(request);
            request.version = KSWORD_ARK_MUTATION_PROTOCOL_VERSION;
            request.flags = getOptionU32(kArgs, L"--flags", 0U);
            request.transactionId = requireOptionU64(kArgs, L"--transaction-id");
            const DWORD kCode = (kSub == L"commit") ? IOCTL_KSWORD_ARK_MUTATION_COMMIT : IOCTL_KSWORD_ARK_MUTATION_ROLLBACK;
            const wchar_t* label = (kSub == L"commit") ? L"IOCTL_KSWORD_ARK_MUTATION_COMMIT" : L"IOCTL_KSWORD_ARK_MUTATION_ROLLBACK";
            if (!sendFixedRequestResponse(kCode, label, request, response, io, GENERIC_READ | GENERIC_WRITE)) return 3;
            printResponseBanner(response.version, response.status, response.lastStatus, io.bytesReturned);
            std::wcout << L"size=" << response.size
                       << L" targetKind=" << response.targetKind
                       << L" pid=" << response.processId
                       << L" bytes=" << response.bytes
                       << L" riskFlags=0x" << std::hex << response.riskFlags
                       << L" transactionId=" << response.transactionId
                       << L" targetAddress=" << hex64(response.targetAddress)
                       << L" targetContext=" << hex64(response.targetContext)
                       << L" beforeHash=" << hex64(response.beforeHash)
                       << L" afterHash=" << hex64(response.afterHash)
                       << std::dec << L" timestampTick=" << response.timestampTick << L"\n";
            printBytesInline(L"beforeBytes", response.beforeBytes, response.bytes);
            printBytesInline(L"afterBytes", response.afterBytes, response.bytes);
            return 0;
        }
        if (kSub == L"query-audit")
        {
            KSWORD_ARK_MUTATION_QUERY_AUDIT_REQUEST request{};
            request.size = sizeof(request);
            request.version = KSWORD_ARK_MUTATION_PROTOCOL_VERSION;
            request.flags = getOptionU32(kArgs, L"--flags", 0U);
            request.maxEntries = getOptionU32(kArgs, L"--max-entries", KSWORD_ARK_MUTATION_AUDIT_RING_CAPACITY);
            request.startSequence = getOptionU64(kArgs, L"--start-sequence", 0ULL);
            std::vector<std::uint8_t> buffer(kLargeResponseBytes, 0U);
            const int kRc = sendRawIoctl(L"IOCTL_KSWORD_ARK_MUTATION_QUERY_AUDIT", IOCTL_KSWORD_ARK_MUTATION_QUERY_AUDIT, &request, sizeof(request), buffer, io);
            if (kRc != 0) return kRc;
            constexpr std::size_t kHeaderSize = sizeof(KSWORD_ARK_MUTATION_QUERY_AUDIT_RESPONSE) - sizeof(KSWORD_ARK_MUTATION_AUDIT_ENTRY);
            const auto* response = reinterpret_cast<const KSWORD_ARK_MUTATION_QUERY_AUDIT_RESPONSE*>(buffer.data());
            std::size_t available = 0U;
            try { available = validateVariable(io.bytesReturned, kHeaderSize, response->entrySize, sizeof(KSWORD_ARK_MUTATION_AUDIT_ENTRY), L"mutation audit"); }
            catch (...) { return 4; }
            printCountHeader(response->version, response->totalCount, response->returnedCount, response->entrySize, io.bytesReturned);
            std::wcout << L"size=" << response->size
                       << L" lostCount=" << response->lostCount
                       << L" oldestSequence=" << response->oldestSequence
                       << L" nextSequence=" << response->nextSequence << L"\n";
            const std::size_t kParsed = responseCountLimit(response->returnedCount, available, getOptionU32(kArgs, L"--limit", 64U));
            for (std::size_t i = 0; i < kParsed; ++i)
            {
                const auto* entry = reinterpret_cast<const KSWORD_ARK_MUTATION_AUDIT_ENTRY*>(buffer.data() + kHeaderSize + (i * response->entrySize));
                std::wcout << L"  [" << i << L"] op=" << entry->operation
                           << L" status=" << entry->status
                           << L" targetKind=" << entry->targetKind
                           << L" pid=" << entry->processId
                           << L" bytes=" << entry->bytes
                           << L" risk=0x" << std::hex << entry->riskFlags
                           << L" flags=0x" << entry->flags
                           << L" transactionId=" << entry->transactionId
                           << L" sequence=" << entry->sequence
                           << L" targetAddress=" << hex64(entry->targetAddress)
                           << L" targetContext=" << hex64(entry->targetContext)
                           << L" beforeHash=" << hex64(entry->beforeHash)
                           << L" afterHash=" << hex64(entry->afterHash)
                           << std::dec << L" timestampTick=" << entry->timestampTick << L"\n";
                if (getOptionBool(kArgs, L"--hexdump"))
                {
                    printBytesInline(L"    byteData", entry->byteData, std::min<std::size_t>(entry->bytes, KSWORD_ARK_MUTATION_MAX_BYTES), 32U);
                }
            }
            return 0;
        }
        std::wcerr << L"error: unknown mutation subcommand '" << kSub << L"'\n";
        return 1;
    }
}

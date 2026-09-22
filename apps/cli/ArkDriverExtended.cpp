#include "ArkDriverExtended.h"

#include "../../shared/ark_client/ArkDriverClient.h"

#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <cwctype>
#include <cwchar>
#include <iomanip>
#include <iostream>
#include <limits>
#include <map>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <utility>

namespace
{
    struct ExtendedArgs
    {
        std::map<std::wstring, std::wstring> options;
    };

    ExtendedArgs parseExtendedArgs(const int argc, wchar_t* const argv[], const int startIndex)
    {
        ExtendedArgs args{};
        for (int index = startIndex; index < argc; ++index)
        {
            if (argv[index] == nullptr || argv[index][0] == L'\0')
            {
                continue;
            }
            if (argv[index][0] != L'-')
            {
                throw std::runtime_error("unexpected positional argument in r0 command");
            }
            const std::wstring kKey = argv[index];
            std::wstring value;
            if (index + 1 < argc && argv[index + 1] != nullptr && argv[index + 1][0] != L'-')
            {
                value = argv[++index];
            }
            args.options[kKey] = value;
        }
        return args;
    }

    bool hasOption(const ExtendedArgs& args, const wchar_t* key)
    {
        return args.options.find(key) != args.options.end();
    }

    std::wstring optionValue(const ExtendedArgs& args, const wchar_t* key, const std::wstring& fallback = {})
    {
        const auto kIt = args.options.find(key);
        return kIt == args.options.end() ? fallback : kIt->second;
    }

    std::wstring requireOption(const ExtendedArgs& args, const wchar_t* key)
    {
        const std::wstring kValue = optionValue(args, key);
        if (kValue.empty())
        {
            throw std::runtime_error("missing required r0 command option");
        }
        return kValue;
    }

    std::uint64_t parseUnsigned(const std::wstring& value, const wchar_t* optionName)
    {
        if (value.empty())
        {
            throw std::runtime_error("numeric r0 command option is empty");
        }
        errno = 0;
        wchar_t* end = nullptr;
        const unsigned long long kParsed = std::wcstoull(value.c_str(), &end, 0);
        if (errno == ERANGE || end == value.c_str() || *end != L'\0')
        {
            (void)optionName;
            throw std::runtime_error("invalid numeric value for r0 command option");
        }
        return static_cast<std::uint64_t>(kParsed);
    }

    std::uint32_t optionU32(const ExtendedArgs& args, const wchar_t* key, const std::uint32_t fallback)
    {
        const std::wstring kValue = optionValue(args, key);
        if (kValue.empty())
        {
            return fallback;
        }
        const std::uint64_t kParsed = parseUnsigned(kValue, key);
        if (kParsed > (std::numeric_limits<std::uint32_t>::max)())
        {
            throw std::runtime_error("r0 command option exceeds uint32 range");
        }
        return static_cast<std::uint32_t>(kParsed);
    }

    std::uint64_t optionU64(const ExtendedArgs& args, const wchar_t* key, const std::uint64_t fallback)
    {
        const std::wstring kValue = optionValue(args, key);
        return kValue.empty() ? fallback : parseUnsigned(kValue, key);
    }

    std::wstring normalizeNtPath(std::wstring path)
    {
        if (path.rfind(L"\\\\?\\", 0U) == 0U)
        {
            return L"\\??\\" + path.substr(4U);
        }
        if (path.rfind(L"\\\\", 0U) == 0U)
        {
            return L"\\??\\UNC\\" + path.substr(2U);
        }
        if (path.size() >= 2U && path[1U] == L':')
        {
            return L"\\??\\" + path;
        }
        return path;
    }

    std::wstring utf8ToWide(const std::string& value)
    {
        if (value.empty())
        {
            return {};
        }
        const int kRequired = ::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), nullptr, 0);
        if (kRequired <= 0)
        {
            return std::wstring(value.begin(), value.end());
        }
        std::wstring result(static_cast<std::size_t>(kRequired), L'\0');
        (void)::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), result.data(), kRequired);
        return result;
    }

    template <typename T, typename = void>
    struct HasUnsupported : std::false_type {};

    template <typename T>
    struct HasUnsupported<T, std::void_t<decltype(std::declval<const T&>().unsupported)>> : std::true_type {};

    template <typename T, typename = void>
    struct HasEntries : std::false_type {};

    template <typename T>
    struct HasEntries<T, std::void_t<decltype(std::declval<const T&>().entries)>> : std::true_type {};

    template <typename Result>
    bool printResultState(const wchar_t* label, const Result& result)
    {
        std::wcout << label << L": io_ok=" << (result.io.ok ? L"true" : L"false")
                   << L" bytes_returned=" << result.io.bytesReturned
                   << L" win32_error=" << result.io.win32Error
                   << L" nt_status=0x" << std::hex << static_cast<std::uint32_t>(result.io.ntStatus)
                   << std::dec << L"\n";
        if constexpr (HasUnsupported<Result>::value)
        {
            std::wcout << L"unsupported=" << (result.unsupported ? L"true" : L"false") << L"\n";
        }
        if constexpr (HasEntries<Result>::value)
        {
            std::wcout << L"returned_rows=" << result.entries.size() << L"\n";
        }
        if (!result.io.message.empty())
        {
            std::wcout << L"detail=" << utf8ToWide(result.io.message) << L"\n";
        }
        return result.io.ok;
    }

    void printBytes(const std::vector<std::uint8_t>& bytes, const std::size_t limit)
    {
        const std::size_t kShown = (std::min)(bytes.size(), limit);
        std::wcout << L"data_hex=";
        for (std::size_t index = 0U; index < kShown; ++index)
        {
            std::wcout << std::hex << std::setw(2) << std::setfill(L'0')
                       << static_cast<unsigned int>(bytes[index]);
        }
        std::wcout << std::dec << std::setfill(L' ') << L"\n";
        if (kShown < bytes.size())
        {
            std::wcout << L"data_hex_truncated=true total_bytes=" << bytes.size() << L"\n";
        }
    }

    void printDirectoryEntries(const std::vector<ksword::ark::DirectoryEntryRecord>& entries, const std::uint32_t limit)
    {
        const std::size_t kShown = (std::min)(entries.size(), static_cast<std::size_t>(limit));
        for (std::size_t index = 0U; index < kShown; ++index)
        {
            const auto& entry = entries[index];
            std::wcout << L"  [" << index << L"] name=" << entry.name
                       << L" size=" << entry.endOfFile
                       << L" attributes=0x" << std::hex << entry.fileAttributes
                       << L" flags=0x" << entry.flags << std::dec << L"\n";
        }
    }

    void printWorkQueueEntries(const std::vector<ksword::ark::WorkQueueEntry>& entries, const std::uint32_t limit)
    {
        const std::size_t kShown = (std::min)(entries.size(), static_cast<std::size_t>(limit));
        for (std::size_t index = 0U; index < kShown; ++index)
        {
            const auto& entry = entries[index];
            std::wcout << L"  [" << index << L"] kind=" << entry.rowKind
                       << L" queue_type=" << entry.queueType
                       << L" tid=" << entry.threadId
                       << L" routine=0x" << std::hex << entry.routineAddress
                       << L" module_base=0x" << entry.moduleBase << std::dec
                       << L" module=" << utf8ToWide(entry.moduleName) << L"\n";
        }
    }

    std::uint32_t parseUnloadedSource(const std::wstring& source)
    {
        if (source.empty() || source == L"mm") return KSWORD_ARK_UNLOADED_DRIVER_SOURCE_MM_UNLOADED_DRIVERS;
        if (source == L"piddb") return KSWORD_ARK_UNLOADED_DRIVER_SOURCE_PIDDB_CACHE_TABLE;
        if (source == L"hash") return KSWORD_ARK_UNLOADED_DRIVER_SOURCE_KERNEL_HASH_BUCKET_LIST;
        throw std::runtime_error("invalid --source, expected mm, piddb, or hash");
    }

    // trimWhitespace removes category-list separators' surrounding whitespace
    // without changing the category token itself.
    std::wstring trimWhitespace(std::wstring value)
    {
        std::size_t first = 0U;
        while (first < value.size() && std::iswspace(value[first]) != 0)
        {
            ++first;
        }
        std::size_t last = value.size();
        while (last > first && std::iswspace(value[last - 1U]) != 0)
        {
            --last;
        }
        return value.substr(first, last - first);
    }

    // parseCallbackMonitorCategories maps a readable comma-separated category
    // list to the shared protocol mask and rejects ambiguous empty entries.
    std::uint32_t parseCallbackMonitorCategories(const ExtendedArgs& args)
    {
        if (!hasOption(args, L"--categories"))
        {
            return KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_CORE;
        }

        const std::wstring kCategoryList = optionValue(args, L"--categories");
        if (kCategoryList.empty())
        {
            throw std::runtime_error("--categories requires a comma-separated category list");
        }

        std::uint32_t categoryMask = 0U;
        std::size_t tokenStart = 0U;
        while (tokenStart <= kCategoryList.size())
        {
            const std::size_t kDelimiter = kCategoryList.find(L',', tokenStart);
            const std::size_t kTokenLength = kDelimiter == std::wstring::npos
                ? kCategoryList.size() - tokenStart
                : kDelimiter - tokenStart;
            const std::wstring kToken = trimWhitespace(kCategoryList.substr(tokenStart, kTokenLength));
            if (kToken.empty())
            {
                throw std::runtime_error("--categories contains an empty category name");
            }
            if (kToken == L"process") categoryMask |= KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_PROCESS;
            else if (kToken == L"thread") categoryMask |= KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_THREAD;
            else if (kToken == L"image") categoryMask |= KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_IMAGE;
            else if (kToken == L"registry") categoryMask |= KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_REGISTRY;
            else if (kToken == L"object") categoryMask |= KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_OBJECT;
            else if (kToken == L"minifilter") categoryMask |= KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_MINIFILTER;
            else if (kToken == L"core") categoryMask |= KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_CORE;
            else if (kToken == L"all") categoryMask |= KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_ALL;
            else throw std::runtime_error("--categories contains an unknown category name");

            if (kDelimiter == std::wstring::npos)
            {
                break;
            }
            tokenStart = kDelimiter + 1U;
        }
        if (categoryMask == 0U)
        {
            throw std::runtime_error("--categories resolved to an empty category mask");
        }
        return categoryMask;
    }

    // printCallbackMonitorStatus emits the fixed monitor state response in the
    // same key=value shape used by the other ArkDriverClient-backed commands.
    void printCallbackMonitorStatus(const ksword::ark::CallbackMonitorStatusResult& result)
    {
        std::wcout << L"version=" << result.version
                   << L" runtime_flags=0x" << std::hex << result.runtimeFlags
                   << L" category_mask=0x" << result.categoryMask
                   << L" registered_category_mask=0x" << result.registeredCategoryMask
                   << std::dec << L" ring_capacity=" << result.ringCapacity
                   << L" queued_count=" << result.queuedCount
                   << L" latest_sequence=" << result.latestSequence
                   << L" dropped_count=" << result.droppedCount
                   << L" last_status=0x" << std::hex << static_cast<std::uint32_t>(result.lastStatus)
                   << L" minifilter_start_status=0x" << static_cast<std::uint32_t>(result.minifilterStartStatus)
                   << std::dec << L"\n";
    }

    // printCallbackMonitorRead emits cursor metadata and a bounded list of
    // validated callback monitor records; the caller can continue at next_sequence.
    void printCallbackMonitorRead(
        const ksword::ark::CallbackMonitorReadResult& result,
        const std::uint32_t limit)
    {
        std::wcout << L"runtime_flags=0x" << std::hex << result.runtimeFlags
                   << L" category_mask=0x" << result.categoryMask
                   << L" response_flags=0x" << result.responseFlags
                   << std::dec << L" ring_capacity=" << result.ringCapacity
                   << L" first_available_sequence=" << result.firstAvailableSequence
                   << L" latest_sequence=" << result.latestSequence
                   << L" next_sequence=" << result.nextSequence
                   << L" dropped_count=" << result.droppedCount
                   << L" lost_before_first=" << result.lostBeforeFirst
                   << L" returned_records=" << result.records.size() << L"\n";

        const std::size_t kShown = (std::min)(result.records.size(), static_cast<std::size_t>(limit));
        for (std::size_t index = 0U; index < kShown; ++index)
        {
            const auto& record = result.records[index];
            std::wcout << L"  [" << index << L"] sequence=" << record.sequence
                       << L" time_utc_100ns=" << record.timeUtc100ns
                       << L" category=0x" << std::hex << record.category
                       << L" operation=0x" << record.operation
                       << L" flags=0x" << record.flags
                       << L" result_status=0x" << static_cast<std::uint32_t>(record.resultStatus)
                       << std::dec << L" originating_pid=" << record.originatingProcessId
                       << L" originating_tid=" << record.originatingThreadId
                       << L" target_pid=" << record.targetProcessId
                       << L" target_tid=" << record.targetThreadId
                       << L" parent_pid=" << record.parentProcessId
                       << L" session_id=" << record.sessionId
                       << L" original_access=0x" << std::hex << record.originalAccess
                       << L" desired_access=0x" << record.desiredAccess
                       << L" object_type=0x" << record.objectType
                       << L" detail_code=0x" << record.detailCode
                       << L" address=0x" << record.address
                       << L" region_size=0x" << record.regionSize
                       << std::dec << L" process_name=" << record.processName
                       << L" path=" << record.path << L"\n";
        }
        if (kShown < result.records.size())
        {
            std::wcout << L"records_truncated=true total_records=" << result.records.size() << L"\n";
        }
    }

    template <typename Result>
    int finishResult(const wchar_t* label, const Result& result)
    {
        return printResultState(label, result) ? 0 : 3;
    }
}

// commandArkDriverExtended implements the read-only R0 commands backed by
// production ArkDriverClient wrappers that were previously desktop-only.
int commandArkDriverExtended(const int argc, wchar_t* argv[])
{
    if (argc < 3 || argv[2] == nullptr)
    {
        std::wcerr << L"error: r0 requires a subcommand\n";
        return 1;
    }

    const std::wstring kSubcommand = argv[2];
    const ExtendedArgs kArgs = parseExtendedArgs(argc, argv, 3);
    const ksword::ark::DriverClient kClient{};
    const std::uint32_t kLimit = optionU32(kArgs, L"--limit", 64U);

    if (kSubcommand == L"workqueue")
    {
        const auto kResult = kClient.enumerateWorkQueues(
            optionU32(kArgs, L"--flags", KSWORD_ARK_WORK_QUEUE_FLAG_INCLUDE_ALL),
            optionU32(kArgs, L"--max-entries", 1024U));
        const int kRc = finishResult(L"workqueue", kResult);
        if (kRc == 0) printWorkQueueEntries(kResult.entries, kLimit);
        return kRc;
    }
    if (kSubcommand == L"directory")
    {
        const auto kResult = kClient.enumerateDirectory(
            normalizeNtPath(requireOption(kArgs, L"--path")),
            optionU32(kArgs, L"--max-entries", 4096U));
        const int kRc = finishResult(L"directory", kResult);
        if (kRc == 0)
        {
            std::wcout << L"filesystem=" << kResult.fileSystemName << L" capped=" << (kResult.capped ? L"true" : L"false") << L"\n";
            printDirectoryEntries(kResult.entries, kLimit);
        }
        return kRc;
    }
    if (kSubcommand == L"directory-irp")
    {
        const auto kResult = kClient.enumerateDirectoryByIrp(
            normalizeNtPath(requireOption(kArgs, L"--path")),
            optionU32(kArgs, L"--layer", KSWORD_ARK_FILE_IRP_LAYER_BASE_FS),
            optionU32(kArgs, L"--max-entries", 4096U));
        const int kRc = finishResult(L"directory-irp", kResult);
        if (kRc == 0)
        {
            std::wcout << L"requested_layer=" << kResult.requestedLayer
                       << L" resolved_layer=" << kResult.resolvedLayer
                       << L" receiver=" << kResult.driverName << L"\n";
            printDirectoryEntries(kResult.entries, kLimit);
        }
        return kRc;
    }
    if (kSubcommand == L"image-signature")
    {
        const auto kResult = kClient.queryImageSignature(
            normalizeNtPath(requireOption(kArgs, L"--path")),
            optionU64(kArgs, L"--module-base", 0ULL),
            optionU32(kArgs, L"--flags", KSWORD_ARK_IMAGE_SIGNATURE_QUERY_FLAG_DEFAULT));
        const int kRc = finishResult(L"image-signature", kResult);
        if (kRc == 0) std::wcout << utf8ToWide(ksword::ark::formatImageSignatureEvidence(kResult)) << L"\n";
        return kRc;
    }
    if (kSubcommand == L"debug-output")
    {
        const auto kResult = kClient.drainDebugOutput(
            optionU64(kArgs, L"--after-sequence", 0ULL),
            optionU32(kArgs, L"--max-records", KSWORD_ARK_DEBUG_OUTPUT_DEFAULT_DRAIN_RECORDS));
        const int kRc = finishResult(L"debug-output", kResult);
        if (kRc == 0)
        {
            std::wcout << L"next_sequence=" << kResult.nextSequence << L" dropped=" << kResult.droppedCount << L"\n";
            const std::size_t kShown = (std::min)(kResult.records.size(), static_cast<std::size_t>(kLimit));
            for (std::size_t index = 0U; index < kShown; ++index)
            {
                const auto& record = kResult.records[index];
                std::wcout << L"  [" << index << L"] sequence=" << record.sequence
                           << L" component=" << record.componentId
                           << L" level=" << record.level
                           << L" text=" << utf8ToWide(record.text) << L"\n";
            }
        }
        return kRc;
    }
    if (kSubcommand == L"hvm-status") return finishResult(L"hvm-status", kClient.queryHvmStatus());
    if (kSubcommand == L"hvm-metrics") return finishResult(L"hvm-metrics", kClient.queryHvmMetrics());
    if (kSubcommand == L"hvm-platform") return finishResult(L"hvm-platform", kClient.hvmPlatform());
    if (kSubcommand == L"hvm-events") return finishResult(L"hvm-events", kClient.queryHvmEvents(optionU64(kArgs, L"--after-sequence", 0ULL), optionU32(kArgs, L"--max-rows", 128U), false));
    if (kSubcommand == L"ioctl-registry") return finishResult(L"ioctl-registry", kClient.queryIoctlRegistry(optionU32(kArgs, L"--flags", KSWORD_ARK_IOCTL_REGISTRY_FLAG_INCLUDE_HANDLER), optionU32(kArgs, L"--max-entries", 512U)));
    if (kSubcommand == L"timer-dpc") return finishResult(L"timer-dpc", kClient.enumerateKernelTimerDpc(optionU32(kArgs, L"--max-entries", KSWORD_ARK_TIMER_DPC_DEFAULT_MAX_ENTRIES), optionU32(kArgs, L"--max-per-bucket", KSWORD_ARK_TIMER_DPC_DEFAULT_BUCKET_BUDGET)));
    if (kSubcommand == L"unloaded") return finishResult(L"unloaded", kClient.queryUnloadedDrivers(parseUnloadedSource(optionValue(kArgs, L"--source", L"mm")), optionU32(kArgs, L"--max-rows", KSWORD_ARK_UNLOADED_DRIVER_DEFAULT_ROWS)));
    if (kSubcommand == L"wfp-events") return finishResult(L"wfp-events", kClient.queryNetworkWfpEvents(optionU64(kArgs, L"--after-sequence", 0ULL), optionU32(kArgs, L"--max-rows", KSWORD_ARK_NETWORK_WFP_EVENT_DEFAULT_REQUESTED_ROWS)));
    if (kSubcommand == L"traffic") return finishResult(L"traffic", kClient.queryNetworkTrafficPackets(optionU64(kArgs, L"--after-sequence", 0ULL), optionU32(kArgs, L"--max-rows", KSWORD_ARK_NETWORK_TRAFFIC_DEFAULT_REQUESTED_ROWS)));
    if (kSubcommand == L"piddb") return finishResult(L"piddb", kClient.queryPiDdb(optionU32(kArgs, L"--max-rows", KSWORD_ARK_PIDDB_DEFAULT_ROWS)));
    if (kSubcommand == L"cpu-power") return finishResult(L"cpu-power", kClient.queryCpuPowerState());
    if (kSubcommand == L"process-protect") return finishResult(L"process-protect", kClient.queryProcessProtectState());
    if (kSubcommand == L"raw-disk-backend") return finishResult(L"raw-disk-backend", kClient.queryRawDiskBackend(optionU32(kArgs, L"--disk", 0U), optionU32(kArgs, L"--backend", KSWORD_ARK_RAW_DISK_BACKEND_WINDOWS_STACK), optionU32(kArgs, L"--flags", 0U)));
    if (kSubcommand == L"raw-disk-read")
    {
        const std::uint64_t kLengthValue = parseUnsigned(requireOption(kArgs, L"--length"), L"--length");
        if (kLengthValue > (std::numeric_limits<std::uint32_t>::max)())
        {
            throw std::runtime_error("raw disk read length exceeds uint32 range");
        }
        const auto kResult = kClient.readRawDisk(
            optionU32(kArgs, L"--disk", 0U),
            optionU32(kArgs, L"--backend", KSWORD_ARK_RAW_DISK_BACKEND_WINDOWS_STACK),
            optionU64(kArgs, L"--offset", 0ULL),
            static_cast<std::uint32_t>(kLengthValue),
            optionU32(kArgs, L"--flags", 0U));
        const int kRc = finishResult(L"raw-disk-read", kResult);
        if (kRc == 0) printBytes(kResult.bytes, hasOption(kArgs, L"--hexdump") ? kResult.bytes.size() : 256U);
        return kRc;
    }
    if (kSubcommand == L"system-time") return finishResult(L"system-time", kClient.querySystemTime());
    if (kSubcommand == L"slat-iommu") return finishResult(L"slat-iommu", kClient.querySlatIommuAudit(hasOption(kArgs, L"--include-mmio")));
    if (kSubcommand == L"platform") return finishResult(L"platform", kClient.queryPlatformAudit(optionU32(kArgs, L"--scope", KSWORD_ARK_PLATFORM_AUDIT_SCOPE_ALL), optionU32(kArgs, L"--max-rows", KSWORD_ARK_PLATFORM_DEFAULT_MAX_ROWS)));
    if (kSubcommand == L"i8042") return finishResult(L"i8042", kClient.queryI8042Audit(optionU32(kArgs, L"--max-rows", KSWORD_ARK_I8042_DEFAULT_MAX_ROWS)));
    if (kSubcommand == L"object-types") return finishResult(L"object-types", kClient.enumObjectTypeTable(optionU32(kArgs, L"--flags", KSWORD_ARK_OBJECT_TYPE_TABLE_FLAG_INCLUDE_ALL), optionU32(kArgs, L"--max-entries", 256U), optionU32(kArgs, L"--start-index", 0U)));
    if (kSubcommand == L"win32k-timers") return finishResult(L"win32k-timers", kClient.queryWin32kTimers(optionU32(kArgs, L"--flags", KSWORD_ARK_WIN32K_QUERY_FLAG_INCLUDE_ALL), optionU32(kArgs, L"--session-id", 0U), optionU32(kArgs, L"--pid", 0U), optionU32(kArgs, L"--tid", 0U), optionU32(kArgs, L"--max-entries", KSWORD_ARK_WIN32K_DEFAULT_MAX_ENTRIES)));
    if (kSubcommand == L"win32k-events") return finishResult(L"win32k-events", kClient.queryWin32kEventHooks(optionU32(kArgs, L"--flags", KSWORD_ARK_WIN32K_QUERY_FLAG_INCLUDE_ALL), optionU32(kArgs, L"--session-id", 0U), optionU32(kArgs, L"--pid", 0U), optionU32(kArgs, L"--tid", 0U), optionU32(kArgs, L"--max-entries", KSWORD_ARK_WIN32K_DEFAULT_MAX_ENTRIES)));

    std::wcerr << L"error: unknown r0 subcommand '" << kSubcommand << L"'\n";
    return 1;
}

// commandArkDriverCallbackMonitor implements the read-only callback monitor
// status and cursor-read operations using the shared R3 client wrapper.
int commandArkDriverCallbackMonitor(const int argc, wchar_t* argv[])
{
    if (argc < 3 || argv[2] == nullptr)
    {
        std::wcerr << L"error: callback monitor requires a subcommand\n";
        return 1;
    }

    const std::wstring kSubcommand = argv[2];
    const ExtendedArgs kArgs = parseExtendedArgs(argc, argv, 3);
    const ksword::ark::DriverClient kClient{};
    if (kSubcommand == L"monitor-start")
    {
        const auto kResult = kClient.controlCallbackMonitor(
            KSWORD_ARK_CALLBACK_MONITOR_ACTION_START,
            parseCallbackMonitorCategories(kArgs));
        const int kRc = finishResult(L"monitor-start", kResult);
        if (kRc == 0) printCallbackMonitorStatus(kResult);
        return kRc;
    }
    if (kSubcommand == L"monitor-stop")
    {
        const auto kResult = kClient.controlCallbackMonitor(
            KSWORD_ARK_CALLBACK_MONITOR_ACTION_STOP,
            0UL);
        const int kRc = finishResult(L"monitor-stop", kResult);
        if (kRc == 0) printCallbackMonitorStatus(kResult);
        return kRc;
    }
    if (kSubcommand == L"monitor-status")
    {
        const auto kResult = kClient.queryCallbackMonitorStatus();
        const int kRc = finishResult(L"monitor-status", kResult);
        if (kRc == 0) printCallbackMonitorStatus(kResult);
        return kRc;
    }
    if (kSubcommand == L"monitor-read")
    {
        const auto kResult = kClient.readCallbackMonitor(
            optionU64(kArgs, L"--after-sequence", 0ULL),
            optionU32(kArgs, L"--max-records", KSWORD_ARK_CALLBACK_MONITOR_DEFAULT_READ_RECORDS));
        const int kRc = finishResult(L"monitor-read", kResult);
        if (kRc == 0) printCallbackMonitorRead(kResult, optionU32(kArgs, L"--limit", 64U));
        return kRc;
    }

    std::wcerr << L"error: unknown callback monitor subcommand '" << kSubcommand << L"'\n";
    return 1;
}

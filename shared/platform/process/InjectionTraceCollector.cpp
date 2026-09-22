#include "InjectionTraceCollector.h"

#include "Process.h"
#include "InjectionStackWalk.h"
#include "../../ark_client/ArkDriverClient.h"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <Psapi.h>
#include <TlHelp32.h>

#include <QElapsedTimer>
#include <QFile>
#include <QFileInfo>
#include <QStringList>

#include <algorithm>
#include <cwchar>
#include <iterator>
#include <map>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#pragma comment(lib, "Advapi32.lib")

namespace ks::process
{
namespace
{
    namespace ev = ksword::evidence;

    // Maximum bytes read in a single comparison. In deep mode, the entire code section is requested; allocating
    // the whole segment directly would turn a 10 MiB module into a single 10 MiB allocation. After slicing, memory
    // usage becomes predictable, and coverage remains unaffected (slices do not overlap and leave no gaps).
    constexpr std::uint32_t kMaxSingleCompareBytes = 1U << 20;

    // How many pages to query in a single QueryWorkingSetEx call.
    constexpr std::size_t kWorkingSetBatchPages = 1024U;

    // ThreadQuerySetWin32StartAddress for NtQueryInformationThread. Documented by Microsoft, but as a potentially
    // changing internal interface, it uses dynamic resolution, return status checks, and a fallback path.
    constexpr LONG kThreadQuerySetWin32StartAddress = 9;

    using NtQueryInformationThreadFn =
        LONG(NTAPI*)(HANDLE, LONG, PVOID, ULONG, PULONG);
    using EnumProcessModulesExFn = BOOL(WINAPI*)(HANDLE, HMODULE*, DWORD, LPDWORD, DWORD);
    using IsWow64Process2Fn = BOOL(WINAPI*)(HANDLE, USHORT*, USHORT*);

    struct ResolvedApi final
    {
        NtQueryInformationThreadFn ntQueryInformationThread = nullptr;
        EnumProcessModulesExFn enumProcessModulesEx = nullptr;
        IsWow64Process2Fn isWow64Process2 = nullptr;
    };

    template <typename T>
    T resolveProc(HMODULE module, const char* name)
    {
        if (module == nullptr)
        {
            return nullptr;
        }
        return reinterpret_cast<T>(reinterpret_cast<void*>(::GetProcAddress(module, name)));
    }

    const ResolvedApi& resolvedApi()
    {
        static const ResolvedApi kApi = []() {
            ResolvedApi resolved;
            const HMODULE kNtdll = ::GetModuleHandleW(L"ntdll.dll");
            resolved.ntQueryInformationThread =
                resolveProc<NtQueryInformationThreadFn>(kNtdll, "NtQueryInformationThread");
            const HMODULE kKernel32 = ::GetModuleHandleW(L"kernel32.dll");
            resolved.enumProcessModulesEx =
                resolveProc<EnumProcessModulesExFn>(kKernel32, "K32EnumProcessModulesEx");
            resolved.isWow64Process2 =
                resolveProc<IsWow64Process2Fn>(kKernel32, "IsWow64Process2");
            if (resolved.enumProcessModulesEx == nullptr)
            {
                const HMODULE kPsapi = ::GetModuleHandleW(L"psapi.dll");
                resolved.enumProcessModulesEx =
                    resolveProc<EnumProcessModulesExFn>(kPsapi, "EnumProcessModulesEx");
            }
            return resolved;
        }();
        return kApi;
    }

    class ScopedHandle final
    {
    public:
        ScopedHandle() = default;
        explicit ScopedHandle(HANDLE handle) : handle_(handle) {}
        ~ScopedHandle() { reset(); }

        ScopedHandle(const ScopedHandle&) = delete;
        ScopedHandle& operator=(const ScopedHandle&) = delete;

        void reset(HANDLE handle = nullptr)
        {
            if (handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE)
            {
                ::CloseHandle(handle_);
            }
            handle_ = handle;
        }

        HANDLE get() const { return handle_; }
        bool valid() const { return handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE; }

    private:
        HANDLE handle_ = nullptr;
    };

    std::uint64_t fileTimeTo100ns(const FILETIME& value)
    {
        ULARGE_INTEGER converted;
        converted.LowPart = value.dwLowDateTime;
        converted.HighPart = value.dwHighDateTime;
        return converted.QuadPart;
    }

    std::uint64_t nowUtc100ns()
    {
        FILETIME now{};
        ::GetSystemTimeAsFileTime(&now);
        return fileTimeTo100ns(now);
    }

    ev::CollectionOutcome win32Failure(const ev::CollectionStatus status, const DWORD error)
    {
        return ev::CollectionOutcome::failure(status, "WIN32", static_cast<std::uint64_t>(error),
                                              std::string());
    }

    // "Executed but did not cover the full request range." No original error
    // code is available—the stop reason is budget or limit, not an API failure.
    ev::CollectionOutcome partialOutcome()
    {
        ev::CollectionOutcome outcome;
        outcome.status = ev::CollectionStatus::kPartial;
        return outcome;
    }

    ev::CollectionOutcome statusOnlyOutcome(const ev::CollectionStatus status)
    {
        ev::CollectionOutcome outcome;
        outcome.status = status;
        return outcome;
    }

    // A device that does not exist at all (driver not installed/loaded) is different from a device that exists but fails on this specific call:
    // The former is a capability limitation, the latter is a coverage gap. The criterion accepts only these two error codes.
    bool deviceIsAbsent(const unsigned long error)
    {
        return error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND;
    }

    ev::CollectionStatus statusForWin32Error(const DWORD error)
    {
        switch (error)
        {
        case ERROR_ACCESS_DENIED:
        case ERROR_PARTIAL_COPY:
            return ev::CollectionStatus::kAccessDenied;
        case ERROR_INVALID_HANDLE:
        case ERROR_INVALID_PARAMETER:
            return ev::CollectionStatus::kError;
        default:
            return ev::CollectionStatus::kError;
        }
    }

    std::string toUtf8(const std::wstring& text)
    {
        return QString::fromWCharArray(text.c_str(), static_cast<int>(text.size())).toStdString();
    }

    // --- Device path -> DOS path ------------------------------------------------- GetMappedFileNameW
    // returns paths in the form \Device\HarddiskVolumeN\.... While the pathsCompatible check at the predicate
    // layer tolerates this difference, display and disk reading require DOS paths. Therefore, we perform a
    // best-effort conversion here; if conversion fails, the original path is retained without fabrication.
    std::wstring deviceToDosPath(const std::wstring& devicePath)
    {
        if (devicePath.empty() || devicePath.rfind(L"\\Device\\", 0U) != 0U)
        {
            return devicePath;
        }
        wchar_t drives[512] = {};
        const DWORD kLength = ::GetLogicalDriveStringsW(
            static_cast<DWORD>(std::size(drives)) - 1U, drives);
        if (kLength == 0U || kLength >= std::size(drives))
        {
            return devicePath;
        }
        for (const wchar_t* drive = drives; *drive != L'\0'; drive += wcslen(drive) + 1U)
        {
            wchar_t letter[3] = { drive[0], L':', L'\0' };
            wchar_t target[MAX_PATH] = {};
            if (::QueryDosDeviceW(letter, target, static_cast<DWORD>(std::size(target))) == 0U)
            {
                continue;
            }
            const std::size_t kTargetLength = wcslen(target);
            if (kTargetLength == 0U || devicePath.size() <= kTargetLength)
            {
                continue;
            }
            if (_wcsnicmp(devicePath.c_str(), target, kTargetLength) == 0 &&
                devicePath[kTargetLength] == L'\\')
            {
                return std::wstring(letter) + devicePath.substr(kTargetLength);
            }
        }
        return devicePath;
    }

    // --- Budget -----------------------------------------------------------------
    struct Budget final
    {
        QElapsedTimer timer;
        std::uint64_t maxDurationMs = 0;
        std::uint64_t maxReadBytes = 0;
        std::uint64_t bytesRead = 0;
        ev::BudgetStop stop = ev::BudgetStop::kContinue;

        bool exhausted()
        {
            if (stop != ev::BudgetStop::kContinue)
            {
                return true;
            }
            if (maxDurationMs != 0U &&
                static_cast<std::uint64_t>(timer.elapsed()) > maxDurationMs)
            {
                stop = ev::BudgetStop::kTimeExhausted;
                return true;
            }
            if (maxReadBytes != 0U && bytesRead > maxReadBytes)
            {
                stop = ev::BudgetStop::kBytesExhausted;
                return true;
            }
            return false;
        }
    };

    // Read target memory. Partial copy (ERROR_PARTIAL_COPY) is common; handle based on 'how much was read'.
    bool readTargetMemory(const HANDLE process,
                          const std::uint64_t address,
                          void* buffer,
                          const std::size_t bytes,
                          Budget& budget,
                          std::size_t* copiedOut)
    {
        if (copiedOut != nullptr)
        {
            *copiedOut = 0U;
        }
        if (bytes == 0U)
        {
            return true;
        }
        SIZE_T copied = 0;
        const BOOL kOk = ::ReadProcessMemory(process, reinterpret_cast<LPCVOID>(address),
                                            buffer, bytes, &copied);
        budget.bytesRead += static_cast<std::uint64_t>(copied);
        if (copiedOut != nullptr)
        {
            *copiedOut = static_cast<std::size_t>(copied);
        }
        return kOk != FALSE && copied == bytes;
    }

    // --- Process Architecture --------------------------------------------------------
    ev::ProcessArchitecture queryProcessArchitecture(const HANDLE process, QString* textOut)
    {
        const ResolvedApi& api = resolvedApi();
        if (api.isWow64Process2 != nullptr)
        {
            USHORT processMachine = IMAGE_FILE_MACHINE_UNKNOWN;
            USHORT nativeMachine = IMAGE_FILE_MACHINE_UNKNOWN;
            if (api.isWow64Process2(process, &processMachine, &nativeMachine) != FALSE)
            {
                if (processMachine == IMAGE_FILE_MACHINE_UNKNOWN)
                {
                    // Non-WOW64: The process architecture is the native architecture.
                    switch (nativeMachine)
                    {
                    case IMAGE_FILE_MACHINE_AMD64:
                        if (textOut != nullptr) { *textOut = QStringLiteral("x64"); }
                        return ev::ProcessArchitecture::kX64;
                    case IMAGE_FILE_MACHINE_ARM64:
                        if (textOut != nullptr) { *textOut = QStringLiteral("ARM64"); }
                        return ev::ProcessArchitecture::kArm64;
                    case IMAGE_FILE_MACHINE_I386:
                        if (textOut != nullptr) { *textOut = QStringLiteral("x86"); }
                        return ev::ProcessArchitecture::kX86Native;
                    default:
                        break;
                    }
                    if (textOut != nullptr) { *textOut = QStringLiteral("unknown"); }
                    return ev::ProcessArchitecture::kUnknown;
                }
                if (textOut != nullptr) { *textOut = QStringLiteral("WOW64 (x86)"); }
                return ev::ProcessArchitecture::kWow64;
            }
        }

        BOOL wow64 = FALSE;
        if (::IsWow64Process(process, &wow64) != FALSE && wow64 != FALSE)
        {
            if (textOut != nullptr) { *textOut = QStringLiteral("WOW64 (x86)"); }
            return ev::ProcessArchitecture::kWow64;
        }
        SYSTEM_INFO info{};
        ::GetNativeSystemInfo(&info);
        if (info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64)
        {
            if (textOut != nullptr) { *textOut = QStringLiteral("x64"); }
            return ev::ProcessArchitecture::kX64;
        }
        if (info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64)
        {
            if (textOut != nullptr) { *textOut = QStringLiteral("ARM64"); }
            return ev::ProcessArchitecture::kArm64;
        }
        if (textOut != nullptr) { *textOut = QStringLiteral("unknown"); }
        return ev::ProcessArchitecture::kUnknown;
    }

    // --- Address Space --------------------------------------------------------
    struct MappedPathCache final
    {
        std::unordered_map<std::uint64_t, std::wstring> byAllocationBase;
        std::unordered_map<std::uint64_t, DWORD> failureByAllocationBase;
    };

    std::wstring queryMappedPath(const HANDLE process,
                                 const std::uint64_t allocationBase,
                                 const std::uint64_t probeAddress,
                                 MappedPathCache& cache,
                                 DWORD* errorOut)
    {
        if (errorOut != nullptr)
        {
            *errorOut = ERROR_SUCCESS;
        }
        const auto kCached = cache.byAllocationBase.find(allocationBase);
        if (kCached != cache.byAllocationBase.end())
        {
            return kCached->second;
        }
        const auto kFailed = cache.failureByAllocationBase.find(allocationBase);
        if (kFailed != cache.failureByAllocationBase.end())
        {
            if (errorOut != nullptr)
            {
                *errorOut = kFailed->second;
            }
            return std::wstring();
        }

        wchar_t buffer[32768] = {};
        const DWORD kLength = ::GetMappedFileNameW(
            process, reinterpret_cast<LPVOID>(probeAddress), buffer,
            static_cast<DWORD>(std::size(buffer)));
        if (kLength == 0U)
        {
            const DWORD kError = ::GetLastError();
            cache.failureByAllocationBase.emplace(allocationBase, kError);
            if (errorOut != nullptr)
            {
                *errorOut = kError;
            }
            return std::wstring();
        }
        std::wstring path = deviceToDosPath(std::wstring(buffer, kLength));
        cache.byAllocationBase.emplace(allocationBase, path);
        return path;
    }

    struct AddressSpaceCollection final
    {
        std::vector<ev::RegionRecord> records;
        ev::CollectionOutcome outcome;
        bool mappedPathFailure = false;
        std::uint64_t highestAddressQueried = 0;
        std::uint64_t lowestAddressQueried = 0;
    };

    AddressSpaceCollection collectAddressSpace(const HANDLE process,
                                               const ev::ProcessInstanceId& owner,
                                               const InjectionTraceOptions& options,
                                               MappedPathCache& cache,
                                               Budget& budget)
    {
        AddressSpaceCollection collection;
        SYSTEM_INFO info{};
        ::GetSystemInfo(&info);
        const std::uint64_t kMinimum =
            reinterpret_cast<std::uint64_t>(info.lpMinimumApplicationAddress);
        const std::uint64_t kMaximum =
            reinterpret_cast<std::uint64_t>(info.lpMaximumApplicationAddress);

        collection.lowestAddressQueried = kMinimum;
        std::uint64_t address = kMinimum;
        std::uint32_t regionCount = 0;
        bool truncated = false;

        while (address <= kMaximum)
        {
            if (budget.exhausted())
            {
                truncated = true;
                break;
            }
            MEMORY_BASIC_INFORMATION mbi{};
            const SIZE_T kQueried = ::VirtualQueryEx(
                process, reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi));
            if (kQueried != sizeof(mbi))
            {
                const DWORD kError = ::GetLastError();
                if (kError == ERROR_INVALID_PARAMETER)
                {
                    break;  // Note: Crossed the end of the user address space; normal termination.
                }
                collection.outcome = win32Failure(statusForWin32Error(kError), kError);
                collection.highestAddressQueried = address;
                return collection;
            }

            const auto kRegionBase = reinterpret_cast<std::uint64_t>(mbi.BaseAddress);
            const auto kRegionSize = static_cast<std::uint64_t>(mbi.RegionSize);
            if (kRegionSize == 0U)
            {
                break;  // Defensive: a zero-length region would cause the loop to hang.
            }

            ev::RegionRecord record;
            record.base = ev::OptionalU64::of(kRegionBase);
            record.size = ev::OptionalU64::of(kRegionSize);
            record.owner = owner;
            record.source = ev::RegionEvidenceSource::kR3VirtualQuery;
            switch (mbi.State)
            {
            case MEM_COMMIT: record.state = ev::RegionState::kCommit; break;
            case MEM_RESERVE: record.state = ev::RegionState::kReserved; break;
            case MEM_FREE: record.state = ev::RegionState::kFree; break;
            default: record.state = ev::RegionState::kUnknown; break;
            }
            switch (mbi.Type)
            {
            case MEM_IMAGE: record.type = ev::RegionType::kImage; break;
            case MEM_MAPPED: record.type = ev::RegionType::kMapped; break;
            case MEM_PRIVATE: record.type = ev::RegionType::kPrivate; break;
            default: record.type = ev::RegionType::kUnknown; break;
            }
            // Free regions have no protection value: Protect is not a valid PAGE_* when the state is MEM_FREE.
            // Writing this would be treated by the predicate layer as an "unrecognizable basic value," which equates meaninglessness with unknown.
            if (record.state != ev::RegionState::kFree)
            {
                record.protection = ev::toRegionProtection(ev::classifyWin32Protection(
                    ev::OptionalU64::of(static_cast<std::uint64_t>(mbi.Protect))));
                record.allocationProtect = ev::toRegionProtection(ev::classifyWin32Protection(
                    ev::OptionalU64::of(static_cast<std::uint64_t>(mbi.AllocationProtect))));
                record.allocationBase = ev::OptionalU64::of(
                    reinterpret_cast<std::uint64_t>(mbi.AllocationBase));
            }

            if (record.state == ev::RegionState::kCommit &&
                (record.type == ev::RegionType::kImage || record.type == ev::RegionType::kMapped))
            {
                DWORD pathError = ERROR_SUCCESS;
                const std::wstring kMapped = queryMappedPath(
                    process, record.allocationBase.valueOr(kRegionBase), kRegionBase, cache,
                    &pathError);
                if (kMapped.empty())
                {
                    // Distinguish two things:
                    //   * MEM_IMAGE has no filename — query must have failed; this is a gap.
                    //   * MEM_MAPPED with ERROR_FILE_INVALID is a **definitive answer** ("this
                    //     mapping is not file-backed," typically a section backed by the page file),
                    //     not a "lookup failure." Counting this as a gap would cause every process
                    //     to remain perpetually incomplete, rendering the gap dimension meaningless.
                    const bool kDefinitelyNotFileBacked =
                        record.type == ev::RegionType::kMapped &&
                        pathError == ERROR_FILE_INVALID;
                    if (!kDefinitelyNotFileBacked)
                    {
                        collection.mappedPathFailure = true;
                    }
                }
                else
                {
                    record.mappedPath = toUtf8(kMapped);
                }
            }

            collection.records.push_back(std::move(record));
            ++regionCount;
            if (regionCount >= options.maxRegionCount)
            {
                truncated = true;
                budget.stop = ev::BudgetStop::kItemsExhausted;
                break;
            }

            const std::uint64_t kNext = kRegionBase + kRegionSize;
            if (kNext <= address)
            {
                break;  // Defensive: stop if not advancing; never infinite loop.
            }
            address = kNext;
            collection.highestAddressQueried = address;
        }

        collection.outcome = truncated
            ? partialOutcome()
            : ev::CollectionOutcome::success();
        return collection;
    }

    // --- Loader view -----------------------------------------------------------
    struct LoaderModule final
    {
        std::wstring path;
        std::uint64_t base = 0;
        std::uint64_t size = 0;
        std::uint32_t entryPointRva = 0;
    };

    struct LoaderCollection final
    {
        std::vector<LoaderModule> modules;
        ev::CollectionOutcome outcome;
    };

    LoaderCollection collectLoaderModules(const HANDLE process)
    {
        LoaderCollection collection;
        const ResolvedApi& api = resolvedApi();
        std::vector<HMODULE> handles(1024U);
        DWORD needed = 0;

        auto enumerate = [&](std::vector<HMODULE>& buffer, DWORD& neededOut) -> BOOL {
            const DWORD kBytes = static_cast<DWORD>(buffer.size() * sizeof(HMODULE));
            if (api.enumProcessModulesEx != nullptr)
            {
                return api.enumProcessModulesEx(process, buffer.data(), kBytes, &neededOut,
                                                LIST_MODULES_ALL);
            }
            return ::EnumProcessModules(process, buffer.data(), kBytes, &neededOut);
        };

        if (enumerate(handles, needed) == FALSE)
        {
            const DWORD kError = ::GetLastError();
            collection.outcome = win32Failure(statusForWin32Error(kError), kError);
            return collection;
        }
        if (needed > handles.size() * sizeof(HMODULE))
        {
            handles.resize(needed / sizeof(HMODULE) + 16U);
            if (enumerate(handles, needed) == FALSE)
            {
                const DWORD kError = ::GetLastError();
                collection.outcome = win32Failure(statusForWin32Error(kError), kError);
                return collection;
            }
        }

        const std::size_t kCount = std::min<std::size_t>(
            handles.size(), static_cast<std::size_t>(needed) / sizeof(HMODULE));
        bool anyFailure = false;
        for (std::size_t i = 0; i < kCount; ++i)
        {
            LoaderModule module;
            wchar_t path[32768] = {};
            if (::GetModuleFileNameExW(process, handles[i], path,
                                       static_cast<DWORD>(std::size(path))) == 0U)
            {
                anyFailure = true;
            }
            else
            {
                module.path = path;
            }
            MODULEINFO info{};
            if (::GetModuleInformation(process, handles[i], &info, sizeof(info)) != FALSE)
            {
                module.base = reinterpret_cast<std::uint64_t>(info.lpBaseOfDll);
                module.size = static_cast<std::uint64_t>(info.SizeOfImage);
                module.entryPointRva = info.EntryPoint != nullptr && info.lpBaseOfDll != nullptr
                    ? static_cast<std::uint32_t>(
                          reinterpret_cast<std::uint64_t>(info.EntryPoint) -
                          reinterpret_cast<std::uint64_t>(info.lpBaseOfDll))
                    : 0U;
            }
            else
            {
                anyFailure = true;
                module.base = reinterpret_cast<std::uint64_t>(handles[i]);
            }
            collection.modules.push_back(std::move(module));
        }

        collection.outcome = anyFailure
            ? partialOutcome()
            : ev::CollectionOutcome::success();
        return collection;
    }

    // --- Thread -----------------------------------------------------------------
    struct ThreadStartCollection final
    {
        std::vector<ev::ThreadStartInput> threads;
        ev::CollectionOutcome outcome;
    };

    ThreadStartCollection collectThreadStarts(const std::uint32_t pid,
                                              const ev::ProcessInstanceId& owner,
                                              const InjectionTraceOptions& options)
    {
        ThreadStartCollection collection;
        const ResolvedApi& api = resolvedApi();

        const ScopedHandle kSnapshot(::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0U));
        if (!kSnapshot.valid())
        {
            const DWORD kError = ::GetLastError();
            collection.outcome = win32Failure(statusForWin32Error(kError), kError);
            return collection;
        }

        THREADENTRY32 entry{};
        entry.dwSize = sizeof(entry);
        if (::Thread32First(kSnapshot.get(), &entry) == FALSE)
        {
            const DWORD kError = ::GetLastError();
            collection.outcome = win32Failure(statusForWin32Error(kError), kError);
            return collection;
        }

        bool anyFailure = false;
        bool truncated = false;
        do
        {
            if (entry.th32OwnerProcessID != pid)
            {
                continue;
            }
            if (collection.threads.size() >= options.maxThreads)
            {
                truncated = true;
                break;
            }

            ev::ThreadStartInput input;
            input.thread.process = owner;
            input.thread.tid = ev::OptionalU64::of(static_cast<std::uint64_t>(entry.th32ThreadID));

            // ThreadQuerySetWin32StartAddress requires THREAD_QUERY_INFORMATION.
            // Opening a handle with THREAD_QUERY_LIMITED_INFORMATION to query this field fails directly (2026-09-12
            // real machine test: all 4 threads returned status=Error). Therefore, first open with the permissions
            // required for this capability; if that fails, fall back to a limited handle. In that case, only the
            // creation time is available, and the start address remains 'not captured' rather than being faked as 0.
            ScopedHandle thread(::OpenThread(
                THREAD_QUERY_INFORMATION, FALSE, entry.th32ThreadID));
            if (!thread.valid())
            {
                thread.reset(::OpenThread(
                    THREAD_QUERY_LIMITED_INFORMATION, FALSE, entry.th32ThreadID));
            }
            if (!thread.valid())
            {
                const DWORD kError = ::GetLastError();
                input.startAddressOutcome = win32Failure(statusForWin32Error(kError), kError);
                anyFailure = true;
                collection.threads.push_back(std::move(input));
                continue;
            }

            FILETIME created{}, exited{}, kernelTime{}, userTime{};
            if (::GetThreadTimes(thread.get(), &created, &exited, &kernelTime, &userTime) != FALSE)
            {
                input.thread.createTime100ns = ev::OptionalU64::of(fileTimeTo100ns(created));
            }

            if (api.ntQueryInformationThread == nullptr)
            {
                // If the interface cannot be resolved, degrade to "not collected" rather than "start address is 0".
                input.startAddressOutcome = statusOnlyOutcome(ev::CollectionStatus::kUnsupported);
                anyFailure = true;
                collection.threads.push_back(std::move(input));
                continue;
            }

            ULONG_PTR startAddress = 0;
            ULONG returned = 0;
            const LONG kStatus = api.ntQueryInformationThread(
                thread.get(), kThreadQuerySetWin32StartAddress, &startAddress,
                static_cast<ULONG>(sizeof(startAddress)), &returned);
            if (kStatus < 0 || returned != sizeof(startAddress))
            {
                input.startAddressOutcome = ev::CollectionOutcome::failure(
                    ev::CollectionStatus::kError, "NTSTATUS",
                    static_cast<std::uint64_t>(static_cast<std::uint32_t>(kStatus)),
                    std::string());
                anyFailure = true;
            }
            else
            {
                input.startAddress =
                    ev::OptionalU64::of(static_cast<std::uint64_t>(startAddress));
                input.startAddressOutcome = ev::CollectionOutcome::success();
            }
            collection.threads.push_back(std::move(input));
        } while (::Thread32Next(kSnapshot.get(), &entry) != FALSE);

        collection.outcome = (anyFailure || truncated)
            ? partialOutcome()
            : ev::CollectionOutcome::success();
        return collection;
    }

    // --- Reference Image ------------------------------------------------------
    struct ReferenceImage final
    {
        ev::PeImageMap map;
        ev::ReferenceConfidence confidence = ev::ReferenceConfidence::kNoReference;
        std::uint64_t base = 0;
        std::string path;
        std::string identityNote;
    };

    // Read two identity fields from the in-memory image header. This is not a second PE parser:
    // it only extracts TimeDateStamp and SizeOfImage from the public IMAGE_DOS_HEADER /
    // IMAGE_NT_HEADERS structures to answer "whether this disk file is the one loaded this time".
    //
    // Note its cyclic nature: the header itself is included in the check range. Therefore, only when both "Disk SizeOfImage ==
    // Loader-reported SizeOfImage" and "Disk TimeDateStamp == Memory TimeDateStamp" hold simultaneously is the verification considered
    // complete; if either is inconsistent, the result must be "reference uncertain" and cannot be automatically classified as malicious.
    bool readInMemoryImageIdentity(const HANDLE process,
                                   const std::uint64_t base,
                                   Budget& budget,
                                   std::uint32_t* timeDateStampOut,
                                   std::uint32_t* sizeOfImageOut)
    {
        IMAGE_DOS_HEADER dos{};
        if (!readTargetMemory(process, base, &dos, sizeof(dos), budget, nullptr))
        {
            return false;
        }
        if (dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew <= 0 ||
            static_cast<std::uint32_t>(dos.e_lfanew) > 0x10000U)
        {
            return false;
        }
        IMAGE_NT_HEADERS64 nt{};
        if (!readTargetMemory(process, base + static_cast<std::uint64_t>(dos.e_lfanew), &nt,
                              sizeof(nt), budget, nullptr))
        {
            return false;
        }
        if (nt.Signature != IMAGE_NT_SIGNATURE)
        {
            return false;
        }
        if (timeDateStampOut != nullptr)
        {
            *timeDateStampOut = nt.FileHeader.TimeDateStamp;
        }
        if (sizeOfImageOut != nullptr)
        {
            // The OptionalHeader layout for 32-bit images differs, and the SizeOfImage location is also different.
            // Check Magic once to avoid reading a 32-bit header using a 64-bit layout.
            if (nt.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
            {
                const auto* optional32 =
                    reinterpret_cast<const IMAGE_OPTIONAL_HEADER32*>(&nt.OptionalHeader);
                *sizeOfImageOut = optional32->SizeOfImage;
            }
            else
            {
                *sizeOfImageOut = nt.OptionalHeader.SizeOfImage;
            }
        }
        return true;
    }

    ReferenceImage buildReferenceImage(const HANDLE process,
                                       const LoaderModule& module,
                                       Budget& budget)
    {
        ReferenceImage reference;
        reference.base = module.base;
        reference.path = toUtf8(module.path);
        if (module.path.empty() || module.base == 0U)
        {
            reference.identityNote = "reference.missing-path";
            return reference;
        }

        QFile file(QString::fromWCharArray(module.path.c_str()));
        if (!file.open(QIODevice::ReadOnly))
        {
            reference.identityNote = "reference.open-failed";
            return reference;
        }
        const QByteArray kBytes = file.readAll();
        if (kBytes.isEmpty())
        {
            reference.identityNote = "reference.empty";
            return reference;
        }

        reference.map = ev::buildPeImageMap(
            reinterpret_cast<const std::uint8_t*>(kBytes.constData()),
            static_cast<std::size_t>(kBytes.size()), module.base);
        if (!reference.map.valid())
        {
            reference.confidence = ev::ReferenceConfidence::kNoReference;
            reference.identityNote = std::string("reference.map-failed:") +
                                     ev::peParseStatusName(reference.map.status);
            return reference;
        }

        std::uint32_t liveTimeDateStamp = 0;
        std::uint32_t liveSizeOfImage = 0;
        const bool kLiveIdentity = readInMemoryImageIdentity(
            process, module.base, budget, &liveTimeDateStamp, &liveSizeOfImage);
        const bool kSizeMatches = module.size != 0U &&
                                 reference.map.header.sizeOfImage ==
                                     static_cast<std::uint32_t>(module.size);
        const bool kStampMatches = kLiveIdentity &&
                                  reference.map.header.timeDateStamp == liveTimeDateStamp;
        if (kSizeMatches && kStampMatches)
        {
            reference.confidence = ev::ReferenceConfidence::kReferenceVerified;
            reference.identityNote = "reference.verified";
        }
        else
        {
            reference.confidence = ev::ReferenceConfidence::kReferenceUncertain;
            reference.identityNote = kLiveIdentity ? "reference.identity-mismatch"
                                                  : "reference.identity-unreadable";
        }
        return reference;
    }

    // --- Payload structure (shallow) ------------------------------------------------------ Whether a page
    // has **no relocation fixup**. Pages with fixups are rewritten by the loader anyway; comparing them
    // against unrelocated content in the section object yields only noise, so the entire page is excluded.
    // The criterion uses the pre-calculated touchedRanges from PeImageMap and the DVRT impact range, avoiding a separate parsing mechanism.
    bool pageHasNoRelocationFixup(const ev::PeImageMap& map,
                                  const std::uint32_t pageRva)
    {
        ev::RvaRange page;
        page.rva = pageRva;
        page.length = 0x1000U;
        const std::vector<ev::RvaRange> kOne{ page };
        if (!ev::intersectRvaRanges(map.relocation.touchedRanges, kOne).empty())
        {
            return false;
        }
        if (!ev::intersectRvaRanges(map.dynamicRelocation.affectedRanges(), kOne).empty())
        {
            return false;
        }
        // Non-comparable ranges (malformed sections, unsupported relocation targets, etc.) are also excluded.
        return ev::intersectRvaRanges(map.notComparableRanges, kOne).empty();
    }

    // Second reference source: Compare live bytes against the section object held by the memory manager.
    //
    // This is not redundant compared to 'compare with disk file'. If a page matches the disk but differs
    // from the section object, it indicates the **disk file was modified after the mapping was created**
    // — the only flaw exposed by techniques that 'modify memory first, then sync the disk file to match'.
    //
    // Coverage is discounted, and the discount is accurately recorded: pages with fixups are not compared, and
    // prototype PTEs that are not in a valid state cannot obtain a reference. Both are counted in
    // sectionPagesRequested/Available; the predicate layer uses this to determine whether 'no differences found' holds.
    void collectSectionObjectComparisons(
        const HANDLE process,
        const std::uint32_t pid,
        const std::map<std::string, ReferenceImage>& references,
        const ev::ComparisonPlan& plan,
        Budget& budget,
        const InjectionTraceOptions& options,
        ev::SurveyInput& input,
        InjectionTraceResult& result)
    {
        static_cast<void>(options);
        const ksword::ark::DriverClient kDriverClient;

        // Each module verifies at most this many pages. The limit is set according to the per-call byte limit in the protocol;
        // one call per module without continuation — this dimension is **sampling verification**, not full comparison.
        constexpr unsigned long kPagesPerModule = KSWORD_ARK_INJECTION_SECTION_BYTES_PAGES_MAX;
        constexpr std::uint64_t kPageBytes = 0x1000ULL;

        std::map<std::string, ev::ImageComparisonOutcome> sectionOutcomes;
        for (const ev::ComparisonTarget& target : plan.targets)
        {
            if (budget.exhausted())
            {
                break;
            }
            const auto kReference = references.find(target.module.imagePath);
            if (kReference == references.end() || !kReference->second.map.valid() ||
                target.range.empty())
            {
                continue;
            }
            if (sectionOutcomes.find(target.module.imagePath) != sectionOutcomes.end())
            {
                continue;   // Sample each module only once.
            }

            // Select pages in this range that lack fixups.
            std::vector<std::uint32_t> pageRvas;
            for (std::uint64_t offset = 0; offset < target.range.length &&
                                           pageRvas.size() < kPagesPerModule;
                 offset += kPageBytes)
            {
                const auto kPageRva =
                    static_cast<std::uint32_t>((target.range.rva + offset) & ~(kPageBytes - 1ULL));
                if (pageHasNoRelocationFixup(kReference->second.map, kPageRva))
                {
                    pageRvas.push_back(kPageRva);
                }
            }
            if (pageRvas.empty())
            {
                continue;   // The entire segment includes fixups: this dimension has no effect on it and generates no entries.
            }

            const std::uint64_t kFirstVa = kReference->second.base + pageRvas.front();
            const std::uint64_t kLastVa = kReference->second.base + pageRvas.back();
            const ksword::ark::ImageSectionPagesResult kPages =
                kDriverClient.readImageSectionPages(
                    pid, kFirstVa, kLastVa + kPageBytes, 0ULL, kPagesPerModule,
                    KSWORD_ARK_INJECTION_SECTION_FLAG_INCLUDE_BYTES);

            ev::ImageComparisonOutcome outcome;
            outcome.module = target.module;
            outcome.referenceSource = ev::ImageReferenceSource::kSectionObject;
            // The identity of the section object reference requires no additional verification: it **is** the section
            // used for this mapping. There is no question of 'whether this file is the one loaded this time'.
            outcome.referenceConfidence = ev::ReferenceConfidence::kReferenceVerified;
            outcome.sectionPagesRequested = pageRvas.size();
            outcome.report.outcome = ev::CollectionOutcome::success();
            outcome.report.conclusion = ev::AnalysisConclusion::kNoDifferenceObserved;

            if (!kPages.io.ok || kPages.pageBytes.empty())
            {
                // No pages were referenced: record the entire entry as 'requested but none succeeded', and suppress the conclusive result at the criterion layer.
                outcome.sectionPagesAvailable = 0U;
                outcome.report.outcome = partialOutcome();
                sectionOutcomes.emplace(target.module.imagePath, std::move(outcome));
                continue;
            }

            // Byte ranges are ordered by valid pages, so iterate through entries in the same order.
            std::size_t validIndex = 0U;
            for (const ksword::ark::ImageSectionPageEntry& entry : kPages.entries)
            {
                if (!entry.bytesPresent())
                {
                    continue;   // Not a valid form: this page has no reference and is not counted as covered.
                }
                const std::size_t kByteOffset = validIndex * kPageBytes;
                ++validIndex;
                if (kByteOffset + kPageBytes > kPages.pageBytes.size())
                {
                    break;
                }
                if (entry.va < kReference->second.base)
                {
                    continue;
                }
                const auto kPageRva = static_cast<std::uint32_t>(entry.va - kReference->second.base);
                if (std::find(pageRvas.begin(), pageRvas.end(), kPageRva) == pageRvas.end())
                {
                    continue;   // This page has a fixup and is not included in the sample set.
                }

                std::vector<std::uint8_t> liveBytes(static_cast<std::size_t>(kPageBytes));
                std::size_t copied = 0U;
                readTargetMemory(process, entry.va, liveBytes.data(), liveBytes.size(),
                                 budget, &copied);
                if (copied != liveBytes.size())
                {
                    continue;   // Real-time page read is incomplete: do not compare, and do not count as covered.
                }
                ++outcome.sectionPagesAvailable;
                ++result.sectionPagesCompared;

                if (std::memcmp(liveBytes.data(), kPages.pageBytes.data() + kByteOffset,
                                liveBytes.size()) == 0)
                {
                    outcome.report.comparedBytes += kPageBytes;
                    continue;
                }

                // Difference. **This page should have zero bytes changed** — it has no fixups, and the content
                // in the section object is exactly the content at the time the mapping was established.
                ev::ImageDiffEntry diff;
                diff.rva = kPageRva;
                diff.va = entry.va;
                diff.length = static_cast<std::uint32_t>(kPageBytes);
                diff.kind = ev::DiffKind::kByteDifference;
                diff.explanation = ev::DiffExplanation::kUnexplained;
                diff.sectionName = ev::sectionNameForRva(kReference->second.map, kPageRva);
                outcome.report.entries.push_back(std::move(diff));
                outcome.report.comparedBytes += kPageBytes;
                outcome.report.differingBytes += kPageBytes;
                outcome.report.conclusion = ev::AnalysisConclusion::kDifferenceObserved;
                ++result.sectionPagesDiffering;
            }
            sectionOutcomes.emplace(target.module.imagePath, std::move(outcome));
        }

        for (auto& item : sectionOutcomes)
        {
            input.imageComparisons.push_back(std::move(item.second));
        }
        result.sectionModulesChecked = static_cast<std::uint32_t>(sectionOutcomes.size());
    }

    ev::PayloadStructure classifyPayloadStructure(const HANDLE process,
                                                  const std::uint64_t base,
                                                  const std::uint64_t size,
                                                  const InjectionTraceOptions& options,
                                                  Budget& budget,
                                                  std::vector<std::string>* factsOut)
    {
        const std::size_t kProbe = static_cast<std::size_t>(
            std::min<std::uint64_t>(size, options.maxPayloadProbeBytes));
        if (kProbe < sizeof(IMAGE_DOS_HEADER))
        {
            return ev::PayloadStructure::kNoStructure;
        }
        std::vector<std::uint8_t> buffer(kProbe);
        std::size_t copied = 0U;
        readTargetMemory(process, base, buffer.data(), buffer.size(), budget, &copied);
        if (copied < sizeof(IMAGE_DOS_HEADER))
        {
            return ev::PayloadStructure::kUnreadable;
        }
        buffer.resize(copied);

        const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(buffer.data());
        if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        {
            // No PE header. For executable non-image memory, we can only say "unknown executable code" here,
            // not "shellcode injection". Identifying stripped payloads is out of scope for this version.
            return ev::PayloadStructure::kBareCode;
        }
        if (dos->e_lfanew <= 0 ||
            static_cast<std::size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS64) > buffer.size())
        {
            if (factsOut != nullptr)
            {
                factsOut->push_back("payload.pe=mz-only");
            }
            // The two-byte 'MZ' signature alone is not sufficient evidence.
            return ev::PayloadStructure::kNoStructure;
        }
        const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(
            buffer.data() + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE)
        {
            if (factsOut != nullptr)
            {
                factsOut->push_back("payload.pe=signature-mismatch");
            }
            return ev::PayloadStructure::kNoStructure;
        }

        const std::uint32_t kSizeOfImage =
            nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC
                ? reinterpret_cast<const IMAGE_OPTIONAL_HEADER32*>(&nt->OptionalHeader)->SizeOfImage
                : nt->OptionalHeader.SizeOfImage;
        if (factsOut != nullptr)
        {
            factsOut->push_back("payload.pe.machine=" +
                                std::to_string(nt->FileHeader.Machine));
            factsOut->push_back("payload.pe.sizeOfImage=" + std::to_string(kSizeOfImage));
            factsOut->push_back("payload.region.size=" + std::to_string(size));
        }
        // If the region fits the declared image span, it resembles 'expanded according to virtual layout'; otherwise,
        // it resembles a PE file lying in a buffer. Both are merely structural facts, not 'already executed'.
        return (kSizeOfImage != 0U && static_cast<std::uint64_t>(kSizeOfImage) <= size)
                   ? ev::PayloadStructure::kMappedPeImage
                   : ev::PayloadStructure::kDataOnlyPeFile;
    }
}

ev::ProcessSurfaceScreen screenProcessInjectionSurface(
    const std::uint32_t pid,
    const std::uint64_t expectedCreationTime100ns)
{
    ev::ProcessSurfaceScreen screen;

    // Verify identity first: if a PID has been reused, report an identity mismatch instead of assigning another process's region count to this row.
    std::uint64_t creationTime100ns = 0U;
    if (!queryProcessCreationTimeByPid(pid, &creationTime100ns, nullptr))
    {
        screen.state = ev::SurfaceScreenState::kAccessDenied;
        return screen;
    }
    if (expectedCreationTime100ns != 0U && expectedCreationTime100ns != creationTime100ns)
    {
        screen.state = ev::SurfaceScreenState::kIdentityMismatch;
        return screen;
    }

    // QUERY_LIMITED_INFORMATION only: this level does not read memory and does not require VM_READ.
    ScopedHandle process(::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
    if (!process.valid())
    {
        const DWORD kError = ::GetLastError();
        screen.state = (kError == ERROR_ACCESS_DENIED)
            ? ev::SurfaceScreenState::kAccessDenied
            : ev::SurfaceScreenState::kFailed;
        return screen;
    }

    ev::ProcessInstanceId owner;
    owner.pid = ev::OptionalU64::of(pid);
    owner.createTime100ns = ev::OptionalU64::of(creationTime100ns);
    owner.bootId = "live";

    Budget budget;
    budget.timer.start();
    budget.maxDurationMs = 5000ULL;   // Single-line hard limit: a stuck line must not crash the entire table.
    budget.maxReadBytes = 0ULL;       // This tier does not read memory.

    InjectionTraceOptions options;
    options.maxRegionCount = 262144U;

    // Critical: Avoid passing MappedPathCache to skip path lookup overhead. collectAddressSpace calls GetMappedFileNameW
    // for IMAGE/MAPPED regions, which is the most expensive operation in this tier. Since filtering only requires type +
    // protection flags, we use a one-time empty cache and accept the path lookup cost. Measurements show the p95 latency
    // of 9.5 ms already includes this; further optimization would split the code path, yielding diminishing returns.
    MappedPathCache pathCache;
    AddressSpaceCollection collection =
        collectAddressSpace(process.get(), owner, options, pathCache, budget);

    const ev::AddressSpaceIndex kIndex =
        ev::buildAddressSpaceIndex(std::move(collection.records), collection.outcome);
    screen = ev::summarizeSurfaceScreen(kIndex, ev::OptionalU64::of(nowUtc100ns()));

    // Post-scan identity verification: If the process exits mid-way and the PID is reused, this line's count must not persist.
    std::uint64_t afterCreation = 0U;
    if (!queryProcessCreationTimeByPid(pid, &afterCreation, nullptr) ||
        afterCreation != creationTime100ns)
    {
        ev::ProcessSurfaceScreen mismatch;
        mismatch.state = ev::SurfaceScreenState::kIdentityMismatch;
        return mismatch;
    }
    return screen;
}

InjectionTraceResult scanProcessInjectionTrace(const std::uint32_t pid,
                                               const std::uint64_t expectedCreationTime100ns,
                                               const QString& fallbackImagePath,
                                               const InjectionTraceOptions& options)
{
    InjectionTraceResult result;
    result.pid = pid;
    result.imagePath = fallbackImagePath;
    // Record the requested mode now: any early return path later will carry it back.
    result.requestedMode = options.deepMode ? ev::SurveyMode::kDeep : ev::SurveyMode::kFast;

    Budget budget;
    budget.timer.start();
    budget.maxDurationMs = options.maxDurationMs;
    budget.maxReadBytes = options.maxReadBytes;

    // --- Identity: Before Start ---------------------------------------------------------
    std::uint64_t creationTime100ns = 0U;
    std::string identityDiagnostic;
    if (!queryProcessCreationTimeByPid(pid, &creationTime100ns, &identityDiagnostic))
    {
        result.status = InjectionTraceStatus::kProcessIdentityUnavailable;
        result.diagnosticText = QString::fromStdString(identityDiagnostic);
        return result;
    }
    if (expectedCreationTime100ns != 0U && expectedCreationTime100ns != creationTime100ns)
    {
        result.status = InjectionTraceStatus::kProcessIdentityMismatch;
        result.diagnosticText = QStringLiteral("expected=%1 actual=%2")
            .arg(expectedCreationTime100ns)
            .arg(creationTime100ns);
        return result;
    }
    result.creationTime100ns = creationTime100ns;

    // --- Handle: Minimize privileges first ---------------------------------------------------
    bool haveQueryInformation = false;
    ScopedHandle process(::OpenProcess(
        PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid));
    if (!process.valid())
    {
        const DWORD kFirstError = ::GetLastError();
        process.reset(::OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid));
        if (!process.valid())
        {
            const DWORD kError = ::GetLastError();
            result.status = kError == ERROR_ACCESS_DENIED
                ? InjectionTraceStatus::kProcessOpenDenied
                : InjectionTraceStatus::kProcessOpenFailed;
            result.diagnosticText = QStringLiteral("OpenProcess limited=%1 full=%2")
                .arg(kFirstError)
                .arg(kError);
            return result;
        }
        haveQueryInformation = true;
    }

    // QueryWorkingSetEx documentation requires PROCESS_QUERY_INFORMATION; PROCESS_QUERY_LIMITED_INFORMATION
    // is insufficient (real machine test on 2026-09-12: no working set pages can be queried under limited
    // handles). Minimal privilege remains the default path: request a wider handle solely for this
    // capability, leave gaps if unavailable, and never escalate the entire collection to higher privileges.
    ScopedHandle workingSetOwner;
    HANDLE workingSetProcess = nullptr;
    if (haveQueryInformation)
    {
        workingSetProcess = process.get();
    }
    else
    {
        workingSetOwner.reset(::OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid));
        if (workingSetOwner.valid())
        {
            workingSetProcess = workingSetOwner.get();
        }
    }

    // Re-check the creation time on the handle to avoid PID reuse between the two calls (TOCTOU).
    {
        FILETIME created{}, exited{}, kernelTime{}, userTime{};
        if (::GetProcessTimes(process.get(), &created, &exited, &kernelTime, &userTime) != FALSE)
        {
            const std::uint64_t kHandleCreation = fileTimeTo100ns(created);
            if (kHandleCreation != creationTime100ns)
            {
                result.status = InjectionTraceStatus::kProcessIdentityMismatch;
                result.diagnosticText = QStringLiteral("handle=%1 snapshot=%2")
                    .arg(kHandleCreation)
                    .arg(creationTime100ns);
                return result;
            }
        }
    }

    ev::ProcessInstanceId owner;
    owner.pid = ev::OptionalU64::of(pid);
    owner.createTime100ns = ev::OptionalU64::of(creationTime100ns);
    owner.bootId = "live";  // Boot identifier within the same runtime; not applicable for cross-boot comparison.
    owner.imageName = QFileInfo(fallbackImagePath).fileName().toStdString();

    // --- Main image path (kernel view) ------------------------------------------------
    std::wstring kernelImagePath;
    {
        wchar_t buffer[32768] = {};
        DWORD size = static_cast<DWORD>(std::size(buffer));
        if (::QueryFullProcessImageNameW(process.get(), 0U, buffer, &size) != FALSE)
        {
            kernelImagePath.assign(buffer, size);
            result.imagePath = QString::fromWCharArray(kernelImagePath.c_str(),
                                                       static_cast<int>(kernelImagePath.size()));
            owner.imageName = QFileInfo(result.imagePath).fileName().toStdString();
        }
    }

    const ev::ProcessArchitecture kArchitecture =
        queryProcessArchitecture(process.get(), &result.architectureText);

    // --- Address Space Index ---------------------------------------------------------
    MappedPathCache pathCache;
    AddressSpaceCollection addressSpace =
        collectAddressSpace(process.get(), owner, options, pathCache, budget);
    result.regionCount = static_cast<std::uint32_t>(addressSpace.records.size());

    ev::SurveyInput input;
    input.mode = options.deepMode ? ev::SurveyMode::kDeep : ev::SurveyMode::kFast;
    input.detectorVersion = "ksword.injection-survey/1.0";
    input.processBefore = owner;
    input.collectedUtc100ns = ev::OptionalU64::of(nowUtc100ns());
    input.targetArchitecture = kArchitecture;
    // The main executable is native x64; this bit is not a guess but a compile-time fact.
    input.collectorArchitecture = ev::CollectorArchitecture::kNative64;

    input.addressSpace =
        ev::buildAddressSpaceIndex(std::move(addressSpace.records), addressSpace.outcome);

    // --- Loader view and image mapping view --------------------------------------------
    const LoaderCollection kLoader = collectLoaderModules(process.get());
    result.loaderModuleCount = static_cast<std::uint32_t>(kLoader.modules.size());

    ev::ModuleCrossViewInput crossInput;
    crossInput.loaderOutcome = kLoader.outcome;
    crossInput.loaderTrust = ev::evaluateModuleEnumerationTrust(
        input.collectorArchitecture, kArchitecture);
    crossInput.imageOutcome = addressSpace.outcome;
    crossInput.payloadOutcome = addressSpace.outcome;
    crossInput.mainImagePathFromKernel = toUtf8(kernelImagePath);

    std::unordered_map<std::uint64_t, const LoaderModule*> loaderByBase;
    for (const LoaderModule& module : kLoader.modules)
    {
        ev::LoaderModuleEntry entry;
        entry.module.imagePath = toUtf8(module.path);
        entry.module.imageBase = ev::OptionalU64::of(module.base);
        entry.module.imageSize = ev::OptionalU64::of(module.size);
        entry.listedName = QFileInfo(QString::fromWCharArray(module.path.c_str()))
                               .fileName()
                               .toStdString();
        entry.isMainImage = crossInput.loaderView.empty();  // The first item in the loader list is the main image.
        if (entry.isMainImage)
        {
            crossInput.mainImagePathFromLoader = entry.module.imagePath;
            crossInput.mainImageBaseFromLoader = entry.module.imageBase;
        }
        loaderByBase.emplace(module.base, &module);
        crossInput.loaderView.push_back(std::move(entry));
    }

    // Image mapping view: aggregate MEM_IMAGE allocations by AllocationBase.
    {
        std::map<std::uint64_t, ev::ImageMappingEntry> imageByBase;
        for (std::size_t i = 0; i < input.addressSpace.entries.size(); ++i)
        {
            const ev::RegionRecord& record = input.addressSpace.entries[i];
            if (record.type != ev::RegionType::kImage ||
                record.state != ev::RegionState::kCommit || !record.allocationBase.present)
            {
                continue;
            }
            const std::uint64_t kBase = record.allocationBase.value;
            ev::ImageMappingEntry& entry = imageByBase[kBase];
            entry.allocationBase = ev::OptionalU64::of(kBase);
            const std::uint64_t kEnd = record.base.valueOr(kBase) + record.size.valueOr(0U);
            const std::uint64_t kSpan = kEnd > kBase ? kEnd - kBase : 0U;
            if (!entry.mappedSize.present || entry.mappedSize.value < kSpan)
            {
                entry.mappedSize = ev::OptionalU64::of(kSpan);
            }
            if (entry.mappedPath.empty() && !record.mappedPath.empty())
            {
                entry.mappedPath = record.mappedPath;
                entry.pathOutcome = ev::CollectionOutcome::success();
            }
        }
        for (auto& item : imageByBase)
        {
            if (item.second.mappedPath.empty())
            {
                const auto kFailure = pathCache.failureByAllocationBase.find(item.first);
                item.second.pathOutcome = kFailure != pathCache.failureByAllocationBase.end()
                    ? win32Failure(statusForWin32Error(kFailure->second), kFailure->second)
                    : statusOnlyOutcome(ev::CollectionStatus::kError);
            }
            if (crossInput.mainImageBaseFromLoader.present &&
                item.first == crossInput.mainImageBaseFromLoader.value)
            {
                crossInput.mainImagePathFromMapping = item.second.mappedPath;
                crossInput.mainImageBaseFromMapping = ev::OptionalU64::of(item.first);
            }
            crossInput.imageView.push_back(item.second);
        }
        result.imageMappingCount = static_cast<std::uint32_t>(crossInput.imageView.size());
    }

    // --- Non-image payload candidates -------------------------------------------------------
    for (std::size_t i = 0; i < input.addressSpace.entries.size() &&
                            i < input.addressSpace.codeClasses.size();
         ++i)
    {
        if (!ev::isDynamicCodeCandidate(input.addressSpace.codeClasses[i]))
        {
            continue;
        }
        const ev::RegionRecord& record = input.addressSpace.entries[i];
        ev::PayloadCandidateEntry candidate;
        candidate.base = record.base;
        candidate.size = record.size;
        candidate.type = record.type;
        if (budget.exhausted())
        {
            candidate.structure = ev::PayloadStructure::kNotExamined;
            candidate.outcome = partialOutcome();
        }
        else
        {
            candidate.structure = classifyPayloadStructure(
                process.get(), record.base.valueOr(0U), record.size.valueOr(0U), options, budget,
                &candidate.structureFacts);
            candidate.outcome = candidate.structure == ev::PayloadStructure::kUnreadable
                ? partialOutcome()
                : ev::CollectionOutcome::success();
        }
        crossInput.payloadView.push_back(candidate);
        input.payloadCandidates.push_back(std::move(candidate));
    }

    // --- Dormant payloads: Non-executable private/mapped memory. Payloads can be stored as RW
    // and converted to RX just before execution (as sleep masks do), so 'only checking pages
    // with current execute permissions' is a genuine blind spot. Deep mode addresses this gap.
    //
    // **Read only the first page of each block, not the entire block**: On the local machine, there are 129937
    // non-executable, committed private/mapped regions across 330 openable processes, totaling 40.9 GB. Reading entire
    // blocks is infeasible; reading only the first page takes 9.3 seconds for the whole machine and about 28 ms per process.
    //
    // Candidates in this tier **do not participate in the final conclusion** (executableAtScanTime=false):
    // in the same measurement, 99 pages passed the PE validity check, averaging ~0.3 per process. Including
    // them in the conclusion path would cause 'observed differences' to appear constantly on clean machines.
    if (options.deepMode)
    {
        std::size_t dormantScanned = 0;
        for (std::size_t i = 0; i < input.addressSpace.entries.size() &&
                                i < input.addressSpace.codeClasses.size();
             ++i)
        {
            if (ev::isDynamicCodeCandidate(input.addressSpace.codeClasses[i]))
            {
                continue;  // Already collected for the executable tier above.
            }
            const ev::RegionRecord& record = input.addressSpace.entries[i];
            if (record.type != ev::RegionType::kPrivate && record.type != ev::RegionType::kMapped)
            {
                continue;  // The image has its own normalization comparison dimension; do not repeat it here.
            }
            if (record.state != ev::RegionState::kCommit || record.size.valueOr(0U) == 0U)
            {
                continue;  // Reserved/free regions contain no readable content.
            }
            const ev::ProtectionFacts kFacts = ev::classifyWin32Protection(record.protection.rawValue);
            if (kFacts.noAccess || kFacts.guard || !kFacts.readable ||
                ev::executeProtectionIsExecutable(kFacts.execute))
            {
                continue;
            }
            if (budget.exhausted())
            {
                break;
            }

            ev::PayloadCandidateEntry candidate;
            candidate.base = record.base;
            candidate.size = record.size;
            candidate.type = record.type;
            candidate.executableAtScanTime = false;
            // Provide only the first page's length to prevent structure classification from reading further.
            candidate.structure = classifyPayloadStructure(
                process.get(), record.base.valueOr(0U),
                std::min<std::uint64_t>(record.size.valueOr(0U), 0x1000ULL), options, budget,
                &candidate.structureFacts);
            candidate.outcome = candidate.structure == ev::PayloadStructure::kUnreadable
                ? partialOutcome()
                : ev::CollectionOutcome::success();
            ++dormantScanned;
            // This tier **retains only PE-shaped payloads**. classifyPayloadStructure returns BareCode for any
            // readable memory without an MZ header—that represents "unknown executable code" for executable memory
            // and "this is data" for data regions. Since there are hundreds of such blocks per process, retaining
            // them would drown out truly noteworthy entries. NoStructure and Unreadable follow the same logic.
            const bool kPeShaped = candidate.structure == ev::PayloadStructure::kMappedPeImage ||
                                  candidate.structure == ev::PayloadStructure::kHeaderErasedPe ||
                                  candidate.structure == ev::PayloadStructure::kDataOnlyPeFile;
            if (!kPeShaped)
            {
                continue;
            }
            input.payloadCandidates.push_back(std::move(candidate));
        }
        // Only count if scanned: if nothing was scanned, this bit must not be set.
        input.nonExecutableMemoryScanned = dormantScanned != 0;
        result.dormantRegionsScanned = static_cast<std::uint32_t>(dormantScanned);
    }

    // Two capabilities not supported in this version are explicitly listed—they narrow the scope of the conclusion but do not suppress it.
    input.extraCapabilityLimitKeys.push_back(ev::kLimitPayloadHeaderErased);
    input.extraCapabilityLimitKeys.push_back(ev::kLimitRuntimeAttribution);
    if (addressSpace.mappedPathFailure)
    {
        input.extraCoverageGapKeys.push_back(ev::kGapMappedPathUnavailable);
    }

    input.moduleCrossView = ev::evaluateModuleCrossView(crossInput);

    // --- Reference image and code extents ---------------------------------------------------
    std::vector<ev::ImageCodeExtent> codeExtents;
    std::map<std::string, ReferenceImage> references;  // key: Module path before normalization.
    for (const LoaderModule& module : kLoader.modules)
    {
        if (budget.exhausted())
        {
            break;
        }
        ReferenceImage reference = buildReferenceImage(process.get(), module, budget);
        ev::ImageCodeExtent extent;
        extent.path = toUtf8(module.path);
        extent.base = module.base;
        extent.size = module.size;
        if (reference.map.valid())
        {
            const std::vector<ev::RvaRange> kExecutable =
                reference.map.executableRawBackedRanges();
            std::uint64_t begin = 0;
            std::uint64_t end = 0;
            bool first = true;
            for (const ev::RvaRange& range : kExecutable)
            {
                if (range.empty())
                {
                    continue;
                }
                if (first)
                {
                    begin = range.rva;
                    end = range.endExclusive();
                    first = false;
                }
                else
                {
                    begin = std::min<std::uint64_t>(begin, range.rva);
                    end = std::max<std::uint64_t>(end, range.endExclusive());
                }
            }
            if (!first)
            {
                extent.codeBeginRva = begin;
                extent.codeEndRva = end;
                extent.codeExtentKnown = true;
            }
            if (extent.size == 0U)
            {
                extent.size = reference.map.header.sizeOfImage;
            }
        }
        codeExtents.push_back(extent);
        references.emplace(extent.path, std::move(reference));
    }

    // --- Thread Start Points ---------------------------------------------------------
    const ThreadStartCollection kThreads = collectThreadStarts(pid, owner, options);
    result.threadCount = static_cast<std::uint32_t>(kThreads.threads.size());
    input.threadEnumerationOutcome = kThreads.outcome;
    input.threadStarts =
        ev::evaluateThreadStarts(kThreads.threads, input.addressSpace, codeExtents);

    // --- Stack walk --------------------------------------------------------------- Only performed in deep
    // mode: it requires unwinding every waiting thread and reading .pdata per module. This cost is incompatible
    // with the "results in seconds" fast mode. If skipped, threadStacks remains empty; the criteria layer will
    // record this as a capability limit rather than a gap—the distinction is documented in InjectionSurvey.h.
    if (options.deepMode && !budget.exhausted())
    {
        StackWalkOptions stackOptions;
        stackOptions.maxThreads = options.maxThreads;
        const StackWalkResult kStacks = walkProcessStacks(
            process.get(), pid, owner, kArchitecture, stackOptions);
        input.threadStacks = kStacks.stacks;
        result.stackThreadsConsidered = kStacks.threadsConsidered;
        result.stackThreadsWaiting = kStacks.threadsWaiting;
        result.stackThreadsWalked = kStacks.threadsWalked;
        if (!kStacks.diagnostic.empty())
        {
            if (!result.diagnosticText.isEmpty())
            {
                result.diagnosticText += QStringLiteral("; ");
            }
            result.diagnosticText += QString::fromStdString(kStacks.diagnostic);
        }
    }

    // --- Working set filtering -----------------------------------------------------------
    std::vector<ev::ComparisonPlanInput::ScreenedPage> screenedPages;
    {
        input.workingSetQueried = workingSetProcess != nullptr;
        bool incomplete = workingSetProcess == nullptr;
        std::size_t queried = 0;
        constexpr std::uint64_t kPageSize = 0x1000ULL;
        for (const ev::ImageCodeExtent& extent : codeExtents)
        {
            if (workingSetProcess == nullptr)
            {
                break;  // If this capability cannot be obtained, the gap is recorded.
            }
            if (!extent.codeExtentKnown || extent.base == 0U)
            {
                // Do not ask about code layout if unknown — even if asked, the answer may not be about the code page.
                incomplete = true;
                continue;
            }
            std::uint64_t rva = extent.codeBeginRva & ~(kPageSize - 1ULL);
            while (rva < extent.codeEndRva)
            {
                if (budget.exhausted())
                {
                    incomplete = true;
                    break;
                }
                std::vector<PSAPI_WORKING_SET_EX_INFORMATION> batch;
                batch.reserve(kWorkingSetBatchPages);
                for (; rva < extent.codeEndRva && batch.size() < kWorkingSetBatchPages;
                     rva += kPageSize)
                {
                    PSAPI_WORKING_SET_EX_INFORMATION item{};
                    item.VirtualAddress = reinterpret_cast<PVOID>(extent.base + rva);
                    batch.push_back(item);
                }
                if (batch.empty())
                {
                    break;
                }
                const DWORD kBytes = static_cast<DWORD>(
                    batch.size() * sizeof(PSAPI_WORKING_SET_EX_INFORMATION));
                if (::QueryWorkingSetEx(workingSetProcess, batch.data(), kBytes) == FALSE)
                {
                    incomplete = true;
                    continue;
                }
                queried += batch.size();
                for (const PSAPI_WORKING_SET_EX_INFORMATION& item : batch)
                {
                    ev::WorkingSetPageFact fact;
                    fact.va = reinterpret_cast<std::uint64_t>(item.VirtualAddress);
                    fact.queried = true;
                    fact.valid = item.VirtualAttributes.Valid != 0U;
                    fact.shared = item.VirtualAttributes.Shared != 0U;
                    fact.shareCount = ev::OptionalU64::of(item.VirtualAttributes.ShareCount);
                    fact.locked = item.VirtualAttributes.Locked != 0U;
                    fact.largePage = item.VirtualAttributes.LargePage != 0U;
                    fact.bad = item.VirtualAttributes.Bad != 0U;
                    fact.win32Protection =
                        ev::OptionalU64::of(item.VirtualAttributes.Win32Protection);
                    fact.node = ev::OptionalU64::of(item.VirtualAttributes.Node);

                    const ev::PageScreenVerdict kVerdict = ev::screenWorkingSetPage(fact);
                    if (kVerdict == ev::PageScreenVerdict::kPrivatizedCandidate)
                    {
                        ++input.workingSetPrivatizedPages;
                    }
                    else if (kVerdict == ev::PageScreenVerdict::kInvalidNeedsRecheck)
                    {
                        ++input.workingSetInvalidPages;
                    }
                    if (ev::pageSelectedForComparison(kVerdict, input.mode))
                    {
                        ev::ComparisonPlanInput::ScreenedPage page;
                        page.imagePath = extent.path;
                        page.pageRva = static_cast<std::uint32_t>(fact.va - extent.base);
                        screenedPages.push_back(page);
                    }
                }
            }
        }
        input.workingSetPagesScreened = queried;
        result.workingSetPagesQueried = static_cast<std::uint32_t>(queried);
        input.workingSetOutcome = incomplete ? partialOutcome()
                                             : ev::CollectionOutcome::success();
    }

    // --- Comparison Plan -------------------------------------------------------------
    ev::ComparisonPlanInput planInput;
    planInput.mode = input.mode;
    planInput.images = codeExtents;
    planInput.screenedPages = screenedPages;
    if (!crossInput.mainImagePathFromLoader.empty())
    {
        planInput.mainImagePath = crossInput.mainImagePathFromLoader;
        const auto kMainReference = references.find(crossInput.mainImagePathFromLoader);
        if (kMainReference != references.end() && kMainReference->second.map.valid())
        {
            planInput.mainImageEntryRva =
                ev::OptionalU64::of(kMainReference->second.map.header.entryPointRva);
        }
        else if (crossInput.mainImageBaseFromLoader.present)
        {
            const auto kMainModule = loaderByBase.find(crossInput.mainImageBaseFromLoader.value);
            if (kMainModule != loaderByBase.end() && kMainModule->second->entryPointRva != 0U)
            {
                planInput.mainImageEntryRva =
                    ev::OptionalU64::of(kMainModule->second->entryPointRva);
            }
        }
    }
    // Enter directed comparison for thread entries with abnormal landing points or first-hop cross-module jumps.
    for (const ev::ThreadStartFinding& start : input.threadStarts)
    {
        if (!start.startAddress.present || start.owningPath.empty())
        {
            continue;
        }
        const bool kInteresting = start.landing == ev::ThreadStartLanding::kImageOutsideCode ||
                                 start.branchLeavesOwningModule;
        if (!kInteresting)
        {
            continue;
        }
        const auto kExtent = std::find_if(
            codeExtents.begin(), codeExtents.end(),
            [&start](const ev::ImageCodeExtent& candidate) {
                return candidate.containsAddress(start.startAddress.value);
            });
        if (kExtent == codeExtents.end())
        {
            continue;
        }
        ev::ComparisonPlanInput::ThreadEntrySite site;
        site.imagePath = kExtent->path;
        site.rva = static_cast<std::uint32_t>(start.startAddress.value - kExtent->base);
        planInput.threadEntrySites.push_back(site);
    }

    const ev::ComparisonPlan kPlan = ev::buildComparisonPlan(planInput);

    // --- Execution Comparison -------------------------------------------------
    {
        std::map<std::string, ev::ImageComparisonOutcome> outcomes;
        std::size_t executed = 0;
        for (const ev::ComparisonTarget& target : kPlan.targets)
        {
            if (executed >= options.maxImageComparisons || budget.exhausted())
            {
                ++input.plannedComparisonsNotRun;
                continue;
            }
            const auto kReference = references.find(target.module.imagePath);
            if (kReference == references.end() || !kReference->second.map.valid())
            {
                ++input.plannedComparisonsNotRun;
                continue;
            }
            if (target.range.empty())
            {
                continue;
            }

            // In depth mode, the target may be the entire code region. Read in fixed-size slices
            // without overlap or gaps, covering the same range as reading the entire segment at once.
            bool targetTruncated = false;
            for (std::uint64_t offset = 0; offset < target.range.length;
                 offset += kMaxSingleCompareBytes)
            {
                if (budget.exhausted())
                {
                    targetTruncated = true;
                    break;
                }
                ev::RvaRange slice;
                slice.rva = target.range.rva + static_cast<std::uint32_t>(offset);
                slice.length = static_cast<std::uint32_t>(std::min<std::uint64_t>(
                    kMaxSingleCompareBytes, target.range.length - offset));

                std::vector<std::uint8_t> liveBytes(slice.length);
                std::size_t copied = 0U;
                readTargetMemory(process.get(), kReference->second.base + slice.rva,
                                 liveBytes.data(), liveBytes.size(), budget, &copied);

                ev::LiveImageBytes live = ev::LiveImageBytes::fromBytes(slice.rva, liveBytes);
                if (copied < liveBytes.size())
                {
                    // Mark unreadable trailing bytes as non-readable; never pad with 00 before comparison.
                    ev::RvaRange hole;
                    hole.rva = slice.rva + static_cast<std::uint32_t>(copied);
                    hole.length = slice.length - static_cast<std::uint32_t>(copied);
                    live.markRange(hole, ev::ByteReadStatus::kUnreadable);
                }

                ev::ImageDiffOptions diffOptions;
                diffOptions.compareRanges = { slice };
                diffOptions.module = target.module;
                diffOptions.evidenceSource = "ksword.injection-survey";
                diffOptions.reference.kind = ev::ReferenceSourceKind::kLocalDisk;
                diffOptions.reference.description = target.module.imagePath;
                diffOptions.collapseGapBytes = 16U;

                const ev::ImageDiffReport kReport =
                    ev::compareImage(kReference->second.map, live, diffOptions);
                ++result.comparedRangeCount;

                ev::ImageComparisonOutcome& merged = outcomes[target.module.imagePath];
                if (merged.module.imagePath.empty())
                {
                    merged.module = target.module;
                    merged.referenceConfidence = kReference->second.confidence;
                    merged.report.outcome = kReport.outcome;
                    merged.report.reference = kReport.reference;
                    merged.report.conclusion = kReport.conclusion;
                }
                merged.report.entries.insert(merged.report.entries.end(),
                                             kReport.entries.begin(), kReport.entries.end());
                merged.report.limitationKeys.insert(merged.report.limitationKeys.end(),
                                                    kReport.limitationKeys.begin(),
                                                    kReport.limitationKeys.end());
                merged.report.comparedBytes += kReport.comparedBytes;
                merged.report.differingBytes += kReport.differingBytes;
                merged.report.unreadableBytes += kReport.unreadableBytes;
                merged.report.excludedBytes += kReport.excludedBytes;
                if (kReport.conclusion == ev::AnalysisConclusion::kDifferenceObserved)
                {
                    merged.report.conclusion = ev::AnalysisConclusion::kDifferenceObserved;
                }
            }
            ++executed;
            if (targetTruncated)
            {
                ++input.plannedComparisonsNotRun;
            }
        }
        for (auto& item : outcomes)
        {
            input.imageComparisons.push_back(std::move(item.second));
        }
        result.comparedModuleCount = static_cast<std::uint32_t>(input.imageComparisons.size());

        // --- Second reference source: Image Section Object. The previous round
        // compared 'live bytes vs. disk file'. This round compares 'live bytes vs.
        // the section object held by the memory manager'. These are not redundant:
        // **A page matching the disk but differing from the section object indicates the disk file was modified after the mapping
        // was established.** This is the only telltale sign of the technique "modify memory, then update the disk file to match."
        //
        // Only compare pages **without relocation fixups**. Pages with fixups are rewritten by the loader anyway, so the live
        // bytes naturally differ from the unrelocated content in the section object; comparing them would only yield noise.
        // The criterion is the pre-computed relocation.touchedRanges from PeImageMap, avoiding a separate parsing routine.
        // Excluded pages are recorded truthfully in the coverage ledger; 'no match' will not be misinterpreted as 'matched with no difference'.
        if (options.deepMode && options.useKernelBackend)
        {
            collectSectionObjectComparisons(
                process.get(), pid, references, kPlan, budget, options, input, result);
        }
    }

    for (const std::string& gap : kPlan.coverageGapKeys)
    {
        input.extraCoverageGapKeys.push_back(gap);
    }

    // --- Target program version identity (for exception rule binding) -----------------------------------
    if (!crossInput.mainImagePathFromLoader.empty())
    {
        const auto kMainReference = references.find(crossInput.mainImagePathFromLoader);
        if (kMainReference != references.end() && kMainReference->second.map.valid())
        {
            ev::DriverInstanceId mainModule;
            mainModule.imagePath = crossInput.mainImagePathFromLoader;
            mainModule.imageSize =
                ev::OptionalU64::of(kMainReference->second.map.header.sizeOfImage);
            mainModule.timeDateStamp =
                ev::OptionalU64::of(kMainReference->second.map.header.timeDateStamp);
            input.targetImageIdentity = ev::moduleIdentityKeyFor(mainModule);
        }
    }

    // --- R0 Scan Backend ------------------------------------------------------
    if (options.useKernelBackend)
    {
        const ksword::ark::DriverClient kDriverClient;
        QStringList diagnostics;
        bool backendAbsent = false;

        // VAD tree. Continue scanning until completion or until our own entry limit is reached.
        ev::KernelVadView vadView;
        {
            std::uint64_t cursorVpn = 0ULL;
            bool first = true;
            bool truncated = false;
            for (;;)
            {
                const ksword::ark::ProcessVadEnumResult kR = kDriverClient.enumerateProcessVad(
                    pid, 0ULL, 0ULL, cursorVpn, options.kernelVadMaxEntries);
                if (!kR.io.ok)
                {
                    if (deviceIsAbsent(kR.io.win32Error))
                    {
                        /*
                         * The local machine does not have a KswordARK device. Since we never declared support for
                         * kernel views on such machines, this is a **capability limitation**, not a coverage gap.
                         * Writing a gap would make scopeIntact always false on machines without the driver, reducing
                         * the four-state logic to three states (as happened with kLimitNonExecutableNotScanned).
                         */
                        backendAbsent = true;
                        vadView = ev::KernelVadView{};
                        diagnostics << QStringLiteral("device absent (%1)").arg(kR.io.win32Error);
                        break;
                    }
                    // Device exists but this call failed (e.g., permissions): this is a genuine gap.
                    vadView.state = ev::KernelBackendState::kDriverUnavailable;
                    vadView.outcome = win32Failure(
                        statusForWin32Error(kR.io.win32Error), kR.io.win32Error);
                    diagnostics << QStringLiteral("vad io error=%1").arg(kR.io.win32Error);
                    break;
                }
                if (first)
                {
                    result.kernelVadState = ev::KernelBackendState::kAvailable;
                    first = false;
                }
                if (kR.profileVerified == 0U ||
                    kR.status == KSWORD_ARK_INJECTION_SCAN_STATUS_DYNDATA_MISSING)
                {
                    // No VadRoot offset verified for the current build — explicitly downgrade, do not guess.
                    vadView.state = ev::KernelBackendState::kProfileUnverified;
                    vadView.outcome = statusOnlyOutcome(ev::CollectionStatus::kUnsupported);
                    vadView.regions.clear();
                    diagnostics << QStringLiteral("vad profile unverified");
                    break;
                }
                for (const ksword::ark::ProcessVadEntry& entry : kR.entries)
                {
                    ev::KernelVadRegion region;
                    region.startVa = ev::OptionalU64::of(entry.startVa);
                    region.endVaExclusive = ev::OptionalU64::of(entry.endVaExclusive);
                    region.vadNodeAddress = ev::OptionalU64::of(entry.vadNodeAddress);
                    region.privateMemory =
                        (entry.entryFlags & KSWORD_ARK_INJECTION_VAD_FLAG_PRIVATE_MEMORY) != 0U;
                    region.hasSection = entry.subsection != 0ULL;
                    region.flagsLayoutAssumed =
                        (entry.entryFlags & KSWORD_ARK_INJECTION_VAD_FLAG_FLAGS_LAYOUT_ASSUMED) != 0U;
                    region.protectionRaw = ev::OptionalU64::of(entry.protection);
                    region.vadFlagsRaw = ev::OptionalU64::of(entry.vadFlagsRaw);
                    vadView.regions.push_back(std::move(region));
                }
                vadView.visitedCount += kR.visitedCount;
                vadView.unreadableNodeCount += kR.unreadableNodeCount;
                if (cursorVpn == 0ULL)
                {
                    // The break-link criterion recognizes only the reading from the **first call**, and is valid only
                    // when it traverses the entire tree. The driver side has already set flags for 'no truncation +
                    // no cursor + no unreadable nodes'; this step further excludes rescan scenarios: if a cursor is
                    // used for a subsequent call, the first `visitedCount` represents only half the tree.
                    vadView.integrityValid = kR.integrityValid;
                    vadView.vadCountKnown = kR.vadCountKnown;
                    vadView.vadHintKnown = kR.vadHintKnown;
                    vadView.vadCount = kR.vadCount;
                    vadView.parentMismatchNodes = kR.parentMismatchNodes;
                    vadView.vadHintVisited = kR.vadHintVisited;
                    vadView.vadHintAddress = kR.vadHintAddress != 0ULL
                        ? ev::OptionalU64::of(kR.vadHintAddress)
                        : ev::OptionalU64{};
                }
                if (kR.status == KSWORD_ARK_INJECTION_SCAN_STATUS_TRUNCATED &&
                    kR.nextCursorVpn != 0ULL &&
                    vadView.regions.size() < options.kernelVadMaxEntries)
                {
                    cursorVpn = kR.nextCursorVpn;
                    // If resuming the scan, the first pass did not traverse the entire tree, so the broken-link criterion is invalidated.
                    vadView.integrityValid = false;
                    continue;
                }
                truncated = (kR.status == KSWORD_ARK_INJECTION_SCAN_STATUS_TRUNCATED);
                vadView.truncated = truncated;
                vadView.state = (truncated || kR.unreadableNodeCount != 0U ||
                                 kR.status == KSWORD_ARK_INJECTION_SCAN_STATUS_PARTIAL)
                    ? ev::KernelBackendState::kPartial
                    : ev::KernelBackendState::kAvailable;
                vadView.outcome = (vadView.state == ev::KernelBackendState::kAvailable)
                    ? ev::CollectionOutcome::success()
                    : partialOutcome();
                break;
            }
            result.kernelVadState = vadView.state;
            result.kernelVadRegionCount = static_cast<std::uint32_t>(vadView.regions.size());
            result.kernelVadUnreadableNodes =
                static_cast<std::uint32_t>(vadView.unreadableNodeCount);
        }

        // User-mode executable page table leaf.
        ev::KernelPteView pteView;
        {
            std::uint64_t cursor = 0ULL;
            bool first = true;
            for (;;)
            {
                const ksword::ark::ProcessExecutablePteScanResult kR =
                    kDriverClient.scanProcessExecutablePte(
                        pid, 0ULL, 0ULL, cursor,
                        options.kernelPteMaxEntries, options.kernelPteMaxTableReads);
                if (!kR.io.ok)
                {
                    if (deviceIsAbsent(kR.io.win32Error))
                    {
                        backendAbsent = true;
                        pteView = ev::KernelPteView{};
                        break;
                    }
                    pteView.state = ev::KernelBackendState::kDriverUnavailable;
                    pteView.outcome = win32Failure(
                        statusForWin32Error(kR.io.win32Error), kR.io.win32Error);
                    diagnostics << QStringLiteral("pte io error=%1").arg(kR.io.win32Error);
                    break;
                }
                if (first)
                {
                    pteView.scannedBegin = ev::OptionalU64::of(kR.scannedBegin);
                    first = false;
                }
                for (const ksword::ark::ProcessExecutablePteEntry& entry : kR.entries)
                {
                    ev::KernelExecutableExtent extent;
                    extent.startVa = ev::OptionalU64::of(entry.startVa);
                    extent.byteLength = ev::OptionalU64::of(entry.byteLength);
                    extent.pageSize = entry.pageSize;
                    extent.executable =
                        (entry.entryFlags & KSWORD_ARK_INJECTION_PTE_ENTRY_FLAG_EXECUTABLE) != 0U;
                    extent.writable =
                        (entry.entryFlags & KSWORD_ARK_INJECTION_PTE_ENTRY_FLAG_WRITABLE) != 0U;
                    extent.userAccessible =
                        (entry.entryFlags & KSWORD_ARK_INJECTION_PTE_ENTRY_FLAG_USER) != 0U;
                    extent.largePage =
                        (entry.entryFlags & KSWORD_ARK_INJECTION_PTE_ENTRY_FLAG_LARGE_PAGE) != 0U;
                    extent.firstEntryValue = ev::OptionalU64::of(entry.firstEntryValue);
                    pteView.extents.push_back(std::move(extent));
                }
                pteView.tableReads += kR.tableReads;
                pteView.failedTableReads += kR.failedTableReads;
                pteView.scannedEnd = ev::OptionalU64::of(kR.scannedEnd);
                result.kernelExecutablePageCount += kR.executablePageCount;
                if (kR.status == KSWORD_ARK_INJECTION_SCAN_STATUS_TRUNCATED &&
                    kR.nextCursorAddress != 0ULL &&
                    pteView.extents.size() < options.kernelPteMaxEntries &&
                    !budget.exhausted())
                {
                    cursor = kR.nextCursorAddress;
                    continue;
                }
                pteView.truncated =
                    (kR.status == KSWORD_ARK_INJECTION_SCAN_STATUS_TRUNCATED);
                pteView.state = (pteView.truncated || kR.failedTableReads != 0U ||
                                 kR.status == KSWORD_ARK_INJECTION_SCAN_STATUS_PARTIAL)
                    ? ev::KernelBackendState::kPartial
                    : ev::KernelBackendState::kAvailable;
                pteView.outcome = (pteView.state == ev::KernelBackendState::kAvailable)
                    ? ev::CollectionOutcome::success()
                    : partialOutcome();
                break;
            }
            result.kernelPteState = pteView.state;
            result.kernelExecutableExtentCount =
                static_cast<std::uint32_t>(pteView.extents.size());
            result.kernelPteTableReads = static_cast<std::uint32_t>(pteView.tableReads);
        }

        if (backendAbsent)
        {
            // No device: treat kernel VADs as 'not requested' and leave only one capability restriction.
            result.kernelVadState = ev::KernelBackendState::kNotRequested;
            result.kernelPteState = ev::KernelBackendState::kNotRequested;
            result.kernelVadRegionCount = 0U;
            result.kernelVadUnreadableNodes = 0U;
            result.kernelExecutableExtentCount = 0U;
            result.kernelExecutablePageCount = 0U;
            result.kernelPteTableReads = 0U;
            input.extraCapabilityLimitKeys.push_back(ev::kLimitKernelBackendAbsent);
        }
        else
        {
            ev::KernelCrossViewInput crossView;
            crossView.r3Index = &input.addressSpace;
            crossView.vadView = std::move(vadView);
            crossView.pteView = std::move(pteView);
            input.kernelCrossView = ev::evaluateKernelCrossView(crossView);
            input.kernelVadState = result.kernelVadState;
            input.kernelPteState = result.kernelPteState;
        }
        result.kernelDiagnosticText = diagnostics.join(QStringLiteral("; "));
    }

    // --- Identity: Verify once again after completion -------------------------------------------------
    {
        ev::ProcessInstanceId after = owner;
        FILETIME created{}, exited{}, kernelTime{}, userTime{};
        if (::GetProcessTimes(process.get(), &created, &exited, &kernelTime, &userTime) != FALSE)
        {
            after.createTime100ns = ev::OptionalU64::of(fileTimeTo100ns(created));
        }
        else
        {
            // If unreadable, downgrade identity verification to 'unconfirmed' instead of defaulting to 'consistent'.
            after.createTime100ns = ev::OptionalU64::unset();
        }
        input.processAfter = after;
    }

    input.budgetStop = budget.stop;
    result.bytesRead = budget.bytesRead;
    result.elapsedMs = static_cast<std::uint64_t>(budget.timer.elapsed());
    result.report = ev::runInjectionSurvey(input);
    result.status = InjectionTraceStatus::kCompleted;
    return result;
}
}

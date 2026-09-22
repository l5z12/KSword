// ============================================================
// HandleUsageTempTest.cpp
// Purpose:
// - Provide an independent console test program to verify the dedicated file usage
//   scanning chain: 'old handle table + DuplicateHandle + GetFinalPathNameByHandleW';
// - Use 16 worker threads plus 1 supervisor thread;
// - When a worker thread has no heartbeat for over 0.5 seconds, the supervisor thread
//   abandons it and resumes creating new threads to scan from 'last progress + 2'.
// ============================================================

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <TlHelp32.h>
#include <winternl.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cwchar>
#include <cwctype>
#include <iostream>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace
{
    // kWorkerCount: Fixed 16 sharding threads, consistent with user-specified policies.
    constexpr std::size_t kWorkerCount = 16;
    // kHeartbeatTimeoutMs: If worker thread 0 has no heartbeat for 0.5 seconds, it is considered stuck.
    constexpr std::uint64_t kHeartbeatTimeoutMs = 500;
    // kMonitorSleepMs: Polling interval for the monitoring thread; kept as short as possible without busy-waiting.
    constexpr DWORD kMonitorSleepMs = 80;

    // SYSTEM_HANDLE_TABLE_ENTRY_INFO_NATIVE：
    // - Align with legacy NtQuerySystemInformation(SystemHandleInformation=16);
    // - This test program retains only the fields required for scanning.
    struct SYSTEM_HANDLE_TABLE_ENTRY_INFO_NATIVE
    {
        ULONG processId = 0;            // processId: The PID of the process that owns this handle.
        UCHAR objectTypeNumber = 0;     // objectTypeNumber: The object type identifier.
        UCHAR flags = 0;                // flags: handle attribute bits.
        USHORT handleValue = 0;         // handleValue: Handle value (previously USHORT).
        PVOID objectAddress = nullptr;  // objectAddress: Kernel object address.
        ACCESS_MASK grantedAccess = 0;  // grantedAccess: access mask.
    };

    // SYSTEM_HANDLE_INFORMATION_NATIVE：
    // - Align with the header returned by the legacy SystemHandleInformation.
    // - handles is a variable-length trailing array.
    struct SYSTEM_HANDLE_INFORMATION_NATIVE
    {
        ULONG handleCount = 0;                                  // handleCount: Total number of system handles.
        SYSTEM_HANDLE_TABLE_ENTRY_INFO_NATIVE handles[1] = {};  // handles: Array of handle entries.
    };

    // UniqueHandle：
    // - Minimal RAII handle wrapper.
    // - Facilitates safe handle release in console test programs across numerous continue branches.
    class UniqueHandle final
    {
    public:
        explicit UniqueHandle(HANDLE handleValue = nullptr)
            : handle_(handleValue)
        {
        }

        ~UniqueHandle()
        {
            reset(nullptr);
        }

        UniqueHandle(const UniqueHandle&) = delete;
        UniqueHandle& operator=(const UniqueHandle&) = delete;

        UniqueHandle(UniqueHandle&& other) noexcept
            : handle_(other.handle_)
        {
            other.handle_ = nullptr;
        }

        UniqueHandle& operator=(UniqueHandle&& other) noexcept
        {
            if (this == &other)
            {
                return *this;
            }
            reset(nullptr);
            handle_ = other.handle_;
            other.handle_ = nullptr;
            return *this;
        }

        HANDLE get() const
        {
            return handle_;
        }

        bool valid() const
        {
            return handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE;
        }

        void reset(HANDLE newHandle)
        {
            if (handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE)
            {
                ::CloseHandle(handle_);
            }
            handle_ = newHandle;
        }

    private:
        HANDLE handle_ = nullptr; // m_handle: Currently held system handle.
    };

    // normalizePathForCompare：
    // - Unified path comparison format.
    // - Handle \\?\ and \\?\UNC\ prefixes.
    // - Convert to backslashes, lowercase, and remove trailing slashes.
    std::wstring normalizePathForCompare(std::wstring text)
    {
        std::replace(text.begin(), text.end(), L'/', L'\\');

        if (text.rfind(L"\\\\?\\UNC\\", 0) == 0)
        {
            text = L"\\\\" + text.substr(8);
        }
        else if (text.rfind(L"\\\\?\\", 0) == 0)
        {
            text = text.substr(4);
        }

        while (text.size() > 3 && !text.empty() && text.back() == L'\\')
        {
            text.pop_back();
        }

        std::transform(
            text.begin(),
            text.end(),
            text.begin(),
            [](wchar_t ch)
            {
                return static_cast<wchar_t>(::towlower(ch));
            });
        return text;
    }

    // getTickMs：
    // - Uniformly read the current millisecond-level timestamp.
    // - Used by heartbeat and monitoring threads to detect 'hangs'.
    std::uint64_t getTickMs()
    {
        return static_cast<std::uint64_t>(::GetTickCount64());
    }

    // g_logMutex：
    // - Protect console debug output;
    // - Avoid console content interleaving caused by multiple threads writing simultaneously.
    std::mutex gLogMutex;

    // logDebug：
    // - Output debug logs in a unified format.
    // - Automatically include timestamps and thread IDs to facilitate observation of thread hangs and rescan behaviors.
    void logDebug(const std::wstring& messageText)
    {
        const std::wstring kFullText =
            L"[DBG tick=" + std::to_wstring(getTickMs()) +
            L" tid=" + std::to_wstring(::GetCurrentThreadId()) +
            L"] " + messageText + L"\r\n";

        std::lock_guard<std::mutex> lock(gLogMutex);
        const HANDLE kStdoutHandle = ::GetStdHandle(STD_OUTPUT_HANDLE);
        if (kStdoutHandle != nullptr && kStdoutHandle != INVALID_HANDLE_VALUE)
        {
            DWORD writtenChars = 0;
            (void)::WriteConsoleW(
                kStdoutHandle,
                kFullText.c_str(),
                static_cast<DWORD>(kFullText.size()),
                &writtenChars,
                nullptr);
            return;
        }

        std::wcout << kFullText;
    }

    // shouldEmitCounterLog：
    // - Throttle failure count logging.
    // - Output on the first 8 calls, then every 256th call, to avoid flooding the console.
    bool shouldEmitCounterLog(const std::size_t countValue)
    {
        return countValue <= 8 || (countValue % 256) == 0;
    }

    // writeConsoleLine：
    // - Stable output of a single line of text to the console;
    // - Avoid inconsistent behavior of std::wcout across different console encodings and buffering modes.
    void writeConsoleLine(const std::wstring& messageText)
    {
        const std::wstring kFullText = messageText + L"\r\n";
        const HANDLE kStdoutHandle = ::GetStdHandle(STD_OUTPUT_HANDLE);
        if (kStdoutHandle != nullptr && kStdoutHandle != INVALID_HANDLE_VALUE)
        {
            DWORD writtenChars = 0;
            if (::WriteConsoleW(
                kStdoutHandle,
                kFullText.c_str(),
                static_cast<DWORD>(kFullText.size()),
                &writtenChars,
                nullptr) != FALSE)
            {
                return;
            }
        }

        std::wcout << kFullText;
    }

    // writeConsoleText：
    // - Output text to the console without automatic line breaks;
    // - For input prompts.
    void writeConsoleText(const std::wstring& messageText)
    {
        const HANDLE kStdoutHandle = ::GetStdHandle(STD_OUTPUT_HANDLE);
        if (kStdoutHandle != nullptr && kStdoutHandle != INVALID_HANDLE_VALUE)
        {
            DWORD writtenChars = 0;
            if (::WriteConsoleW(
                kStdoutHandle,
                messageText.c_str(),
                static_cast<DWORD>(messageText.size()),
                &writtenChars,
                nullptr) != FALSE)
            {
                return;
            }
        }

        std::wcout << messageText;
        std::wcout.flush();
    }

    // readConsoleLine：
    // - Prefer using ReadConsoleW to read interactive console input.
    // - If not an interactive console, fall back to std::getline to facilitate pipe testing.
    bool readConsoleLine(std::wstring& textOut)
    {
        textOut.clear();

        const HANDLE kStdinHandle = ::GetStdHandle(STD_INPUT_HANDLE);
        DWORD consoleMode = 0;
        if (kStdinHandle == nullptr ||
            kStdinHandle == INVALID_HANDLE_VALUE ||
            ::GetConsoleMode(kStdinHandle, &consoleMode) == FALSE)
        {
            return static_cast<bool>(std::getline(std::wcin, textOut));
        }

        std::vector<wchar_t> buffer(8192, L'\0');
        DWORD readChars = 0;
        if (::ReadConsoleW(
            kStdinHandle,
            buffer.data(),
            static_cast<DWORD>(buffer.size() - 1),
            &readChars,
            nullptr) == FALSE)
        {
            return false;
        }

        textOut.assign(buffer.data(), buffer.data() + readChars);
        while (!textOut.empty() &&
            (textOut.back() == L'\r' || textOut.back() == L'\n' || textOut.back() == L'\0'))
        {
            textOut.pop_back();
        }
        return true;
    }

    // getProcessNameMap：
    // - Build PID -> process name mapping in one go
    // - Avoid re-traversing the ToolHelp snapshot every time results are printed.
    std::unordered_map<std::uint32_t, std::wstring> getProcessNameMap()
    {
        std::unordered_map<std::uint32_t, std::wstring> resultMap;
        UniqueHandle snapshotHandle(::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
        if (!snapshotHandle.valid())
        {
            return resultMap;
        }

        PROCESSENTRY32W processEntry{};
        processEntry.dwSize = sizeof(processEntry);
        BOOL hasItem = ::Process32FirstW(snapshotHandle.get(), &processEntry);
        while (hasItem != FALSE)
        {
            resultMap[processEntry.th32ProcessID] = processEntry.szExeFile;
            hasItem = ::Process32NextW(snapshotHandle.get(), &processEntry);
        }
        return resultMap;
    }

    // enableDebugPrivilege：
    // - Enables SeDebugPrivilege for the current process.
    // - To facilitate higher success rates for cross-process DuplicateHandle operations.
    bool enableDebugPrivilege()
    {
        HANDLE rawTokenHandle = nullptr;
        if (::OpenProcessToken(
            ::GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &rawTokenHandle) == FALSE)
        {
            return false;
        }

        UniqueHandle tokenHandle(rawTokenHandle);
        LUID privilegeLuid{};
        if (::LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &privilegeLuid) == FALSE)
        {
            return false;
        }

        TOKEN_PRIVILEGES tokenPrivileges{};
        tokenPrivileges.PrivilegeCount = 1;
        tokenPrivileges.Privileges[0].Luid = privilegeLuid;
        tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        if (::AdjustTokenPrivileges(
            tokenHandle.get(),
            FALSE,
            &tokenPrivileges,
            sizeof(tokenPrivileges),
            nullptr,
            nullptr) == FALSE)
        {
            return false;
        }

        return ::GetLastError() == ERROR_SUCCESS;
    }

    // querySystemHandles：
    // - Call the legacy SystemHandleInformation(16) to capture a system handle snapshot;
    // - Returns the entire buffer for read-only sharing across all threads.
    bool querySystemHandles(std::vector<std::uint8_t>& bufferOut)
    {
        bufferOut.clear();

        using NtQuerySystemInformationFn = NTSTATUS(NTAPI*)(ULONG, PVOID, ULONG, PULONG);
        const HMODULE kNtdllModule = ::GetModuleHandleW(L"ntdll.dll");
        if (kNtdllModule == nullptr)
        {
            return false;
        }

        const auto kQuerySystemInformation =
            reinterpret_cast<NtQuerySystemInformationFn>(
                ::GetProcAddress(kNtdllModule, "NtQuerySystemInformation"));
        if (kQuerySystemInformation == nullptr)
        {
            return false;
        }

        ULONG bufferSize = 0x10000;
        for (int attemptIndex = 0; attemptIndex < 12; ++attemptIndex)
        {
            bufferOut.assign(bufferSize, 0);
            NTSTATUS status = kQuerySystemInformation(16, bufferOut.data(), bufferSize, nullptr);
            if (status == static_cast<NTSTATUS>(0xC0000004))
            {
                bufferSize *= 2;
                continue;
            }
            return status >= 0;
        }
        return false;
    }

    // openTargetPathHandle：
    // - Open the target path with shared read/write and delete access;
    // - Directories automatically include FILE_FLAG_BACKUP_SEMANTICS.
    bool openTargetPathHandle(
        const std::wstring& inputPath,
        const bool directoryMode,
        UniqueHandle& handleOut)
    {
        handleOut.reset(nullptr);
        const DWORD kFlags = directoryMode ? FILE_FLAG_BACKUP_SEMANTICS : 0;
        HANDLE rawHandle = ::CreateFileW(
            inputPath.c_str(),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr,
            OPEN_EXISTING,
            kFlags,
            nullptr);
        if (rawHandle == INVALID_HANDLE_VALUE || rawHandle == nullptr)
        {
            return false;
        }
        handleOut.reset(rawHandle);
        return true;
    }

    // resolveFileTypeIndex：
    // - Open the target path first to obtain the 'current process handle value';
    // - Then locate the objectTypeNumber corresponding to that handle from the system handle table.
    // - Dynamically determine the File TypeIndex based on this.
    bool resolveFileTypeIndex(
        const HANDLE localTargetHandle,
        const SYSTEM_HANDLE_INFORMATION_NATIVE* handleInfo,
        std::uint8_t& fileTypeIndexOut)
    {
        fileTypeIndexOut = 0;
        if (localTargetHandle == nullptr || localTargetHandle == INVALID_HANDLE_VALUE || handleInfo == nullptr)
        {
            return false;
        }

        const DWORD kCurrentProcessId = ::GetCurrentProcessId();
        const USHORT kLocalHandleValue = static_cast<USHORT>(reinterpret_cast<ULONG_PTR>(localTargetHandle));
        for (ULONG index = 0; index < handleInfo->handleCount; ++index)
        {
            const SYSTEM_HANDLE_TABLE_ENTRY_INFO_NATIVE& row = handleInfo->handles[index];
            if (row.processId != kCurrentProcessId)
            {
                continue;
            }
            if (row.handleValue != kLocalHandleValue)
            {
                continue;
            }

            fileTypeIndexOut = row.objectTypeNumber;
            return fileTypeIndexOut != 0;
        }
        return false;
    }

    // MatchRecord：
    // - Saves the final output record of a single match.
    // - Unified printing at the end by the main thread to avoid console output disorder in multi-threaded scenarios.
    struct MatchRecord
    {
        std::uint32_t processId = 0;    // processId: Hit process PID.
        std::wstring processName;       // processName: Hit process name.
        std::uint64_t handleValue = 0;  // handleValue: Matched handle value.
        std::wstring finalPath;         // finalPath: The final DOS path after a match.
        std::size_t sourceIndex = 0;    // sourceIndex: entry index in the original handle table.
    };

    // SharedScanState：
    // - Read-only scan context and result aggregation area shared by all worker threads;
    // - Threads read-only access the handle table; only write to the result area with a lock.
    struct SharedScanState
    {
        const SYSTEM_HANDLE_INFORMATION_NATIVE* handleInfo = nullptr; // handleInfo: Snapshot of the system handle table.
        std::size_t handleCount = 0;                                  // handleCount: Number of handle entries.
        std::uint8_t fileTypeIndex = 0;                               // fileTypeIndex: File type index dynamically resolved.
        bool directoryMode = false;                                   // directoryMode: Whether the target is a directory.
        std::wstring normalizedTargetPath;                            // normalizedTargetPath: Normalized target path.
        std::unordered_map<std::uint32_t, std::wstring> processNameMap; // processNameMap: PID -> Process name.

        std::mutex resultMutex;                                       // resultMutex: protects the result collection
        std::vector<MatchRecord> matchList;                           // matchList: Match results list.
        std::unordered_set<std::uint64_t> emittedHandleKeySet;        // emittedHandleKeySet: Deduplicated set of PID+Handle keys.

        std::atomic<std::size_t> openProcessFailedCount = 0;          // openProcessFailedCount: Count of OpenProcess failures.
        std::atomic<std::size_t> duplicateFailedCount = 0;            // duplicateFailedCount: Count of DuplicateHandle failures.
        std::atomic<std::size_t> pathQueryFailedCount = 0;            // pathQueryFailedCount: Number of path query failures.
        std::atomic<std::size_t> nonDiskFileSkippedCount = 0;         // nonDiskFileSkippedCount: Count of non-disk file handles skipped.
        std::atomic<std::size_t> timeoutRespawnCount = 0;             // timeoutRespawnCount: Number of times the supervising thread rescanned due to a hang.
    };

    // WorkerAttempt：
    // - Represents a single thread attempt for a specific sharding task.
    // - If a thread hangs, it will not be forcibly killed; instead, it will be marked as abandoned and resumed by the supervisor thread.
    struct WorkerAttempt
    {
        std::size_t slotId = 0;                                       // slotId: shard ID.
        std::size_t startIndex = 0;                                   // startIndex: Starting scan index for this attempt.
        std::size_t endIndex = 0;                                     // endIndex: Scan end index for this attempt.
        std::atomic<std::size_t> progressIndex = 0;                   // progressIndex: Current index written before scanning.
        std::atomic<std::uint64_t> lastAliveTickMs = 0;               // lastAliveTickMs: timestamp of the most recent heartbeat.
        std::atomic<bool> completed = false;                          // completed: Whether the current attempt has completed normally.
        std::atomic<bool> abandoned = false;                          // abandoned: Whether the monitoring thread has timed out and abandoned the operation.
    };

    // WorkerSlotState：
    // - Record the current active attempt for a shard.
    // - The supervising thread will replace this with a new retry attempt here.
    struct WorkerSlotState
    {
        std::size_t slotId = 0;                                       // slotId: Shard ID.
        std::size_t rangeBegin = 0;                                   // rangeBegin: Starting index of the shard.
        std::size_t rangeEnd = 0;                                     // rangeEnd: End index of the shard.
        std::shared_ptr<WorkerAttempt> activeAttempt;                 // activeAttempt: current active attempt.
        bool finished = false;                                        // finished: Whether this shard is complete.
    };

    // buildHandleKey：
    // - Construct a deduplicated key from PID + Handle;
    // - Prevent the monitoring thread from recording the same handle again after resuming the scan.
    std::uint64_t buildHandleKey(const SYSTEM_HANDLE_TABLE_ENTRY_INFO_NATIVE& row)
    {
        return (static_cast<std::uint64_t>(row.processId) << 32) ^
            static_cast<std::uint64_t>(row.handleValue);
    }

    // workerThreadProc：
    // - Worker thread body;
    // - Writes a heartbeat and progress before each scan;
    // - If marked as abandoned by the supervising thread, actively stop at the next return point.
    void workerThreadProc(
        const std::shared_ptr<WorkerAttempt>& attempt,
        SharedScanState* sharedState)
    {
        if (attempt == nullptr || sharedState == nullptr || sharedState->handleInfo == nullptr)
        {
            return;
        }

        {
            std::wstringstream stream;
            stream
                << L"worker start"
                << L" slot=" << attempt->slotId
                << L" range=[" << attempt->startIndex << L"," << attempt->endIndex << L"]";
            logDebug(stream.str());
        }

        for (std::size_t index = attempt->startIndex; index <= attempt->endIndex; ++index)
        {
            if (attempt->abandoned.load())
            {
                std::wstringstream stream;
                stream
                    << L"worker abandoned"
                    << L" slot=" << attempt->slotId
                    << L" progress=" << attempt->progressIndex.load();
                logDebug(stream.str());
                return;
            }

            attempt->progressIndex.store(index);
            attempt->lastAliveTickMs.store(getTickMs());

            if (((index - attempt->startIndex) % 8192) == 0)
            {
                std::wstringstream stream;
                stream
                    << L"worker progress"
                    << L" slot=" << attempt->slotId
                    << L" index=" << index
                    << L" end=" << attempt->endIndex;
                logDebug(stream.str());
            }

            const SYSTEM_HANDLE_TABLE_ENTRY_INFO_NATIVE& row = sharedState->handleInfo->handles[index];
            if (row.objectTypeNumber != sharedState->fileTypeIndex)
            {
                continue;
            }

            UniqueHandle ownerProcessHandle(::OpenProcess(PROCESS_DUP_HANDLE, FALSE, row.processId));
            if (!ownerProcessHandle.valid())
            {
                const std::size_t kFailCount = sharedState->openProcessFailedCount.fetch_add(1) + 1;
                if (shouldEmitCounterLog(kFailCount))
                {
                    std::wstringstream stream;
                    stream
                        << L"OpenProcess failed"
                        << L" slot=" << attempt->slotId
                        << L" index=" << index
                        << L" pid=" << row.processId
                        << L" error=" << ::GetLastError()
                        << L" count=" << kFailCount;
                    logDebug(stream.str());
                }
                continue;
            }

            HANDLE duplicatedHandleRaw = nullptr;
            const BOOL kDuplicateOk = ::DuplicateHandle(
                ownerProcessHandle.get(),
                reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(row.handleValue)),
                ::GetCurrentProcess(),
                &duplicatedHandleRaw,
                0,
                FALSE,
                DUPLICATE_SAME_ACCESS);
            if (kDuplicateOk == FALSE || duplicatedHandleRaw == nullptr)
            {
                const std::size_t kFailCount = sharedState->duplicateFailedCount.fetch_add(1) + 1;
                if (shouldEmitCounterLog(kFailCount))
                {
                    std::wstringstream stream;
                    stream
                        << L"DuplicateHandle failed"
                        << L" slot=" << attempt->slotId
                        << L" index=" << index
                        << L" pid=" << row.processId
                        << L" handle=0x" << std::hex << row.handleValue << std::dec
                        << L" error=" << ::GetLastError()
                        << L" count=" << kFailCount;
                    logDebug(stream.str());
                }
                continue;
            }

            UniqueHandle duplicatedHandle(duplicatedHandleRaw);
            if (::GetFileType(duplicatedHandle.get()) != FILE_TYPE_DISK)
            {
                const std::size_t kSkipCount = sharedState->nonDiskFileSkippedCount.fetch_add(1) + 1;
                if (shouldEmitCounterLog(kSkipCount))
                {
                    std::wstringstream stream;
                    stream
                        << L"non-disk file handle skipped"
                        << L" slot=" << attempt->slotId
                        << L" index=" << index
                        << L" pid=" << row.processId
                        << L" handle=0x" << std::hex << row.handleValue << std::dec
                        << L" count=" << kSkipCount;
                    logDebug(stream.str());
                }
                continue;
            }

            // Refresh the heartbeat again before a potential hang point to allow the monitoring thread to locate the actual hang point as closely as possible.
            attempt->progressIndex.store(index);
            attempt->lastAliveTickMs.store(getTickMs());

            wchar_t finalPathBuffer[32768] = {};
            const DWORD kFinalPathLength = ::GetFinalPathNameByHandleW(
                duplicatedHandle.get(),
                finalPathBuffer,
                static_cast<DWORD>(std::size(finalPathBuffer)),
                VOLUME_NAME_DOS);
            if (kFinalPathLength == 0 || kFinalPathLength >= std::size(finalPathBuffer))
            {
                const DWORD kLastError = ::GetLastError();
                const std::size_t kFailCount = sharedState->pathQueryFailedCount.fetch_add(1) + 1;
                if (shouldEmitCounterLog(kFailCount))
                {
                    std::wstringstream stream;
                    stream
                        << L"GetFinalPathNameByHandleW failed"
                        << L" slot=" << attempt->slotId
                        << L" index=" << index
                        << L" pid=" << row.processId
                        << L" handle=0x" << std::hex << row.handleValue << std::dec
                        << L" len=" << kFinalPathLength
                        << L" error=" << kLastError
                        << L" count=" << kFailCount;
                    logDebug(stream.str());
                }
                continue;
            }

            std::wstring normalizedFinalPath = normalizePathForCompare(finalPathBuffer);
            bool matched = false;
            if (sharedState->directoryMode)
            {
                matched = normalizedFinalPath == sharedState->normalizedTargetPath ||
                    normalizedFinalPath.rfind(sharedState->normalizedTargetPath + L"\\", 0) == 0;
            }
            else
            {
                matched = normalizedFinalPath == sharedState->normalizedTargetPath;
            }

            if (!matched)
            {
                continue;
            }

            const std::uint64_t kHandleKey = buildHandleKey(row);
            std::lock_guard<std::mutex> lock(sharedState->resultMutex);
            if (sharedState->emittedHandleKeySet.find(kHandleKey) != sharedState->emittedHandleKeySet.end())
            {
                continue;
            }

            sharedState->emittedHandleKeySet.insert(kHandleKey);
            MatchRecord record{};
            record.processId = row.processId;
            record.handleValue = row.handleValue;
            record.sourceIndex = index;
            const auto kProcessNameIt = sharedState->processNameMap.find(row.processId);
            if (kProcessNameIt != sharedState->processNameMap.end())
            {
                record.processName = kProcessNameIt->second;
            }
            else
            {
            record.processName = L"PID_" + std::to_wstring(row.processId);
            }
            record.finalPath = finalPathBuffer;
            sharedState->matchList.push_back(std::move(record));

            std::wstringstream stream;
            stream
                << L"match found"
                << L" slot=" << attempt->slotId
                << L" index=" << index
                << L" pid=" << row.processId
                << L" handle=0x" << std::hex << row.handleValue << std::dec
                << L" path=" << finalPathBuffer;
            logDebug(stream.str());
        }

        attempt->completed.store(true);
        attempt->lastAliveTickMs.store(getTickMs());

        {
            std::wstringstream stream;
            stream
                << L"worker completed"
                << L" slot=" << attempt->slotId
                << L" finalProgress=" << attempt->progressIndex.load();
            logDebug(stream.str());
        }
    }

    // startAttempt：
    // - Create a new scan attempt for a specific shard.
    // - Threads use detach to avoid blocking the join operation before process exit, which could deadlock the thread.
    std::shared_ptr<WorkerAttempt> startAttempt(
        const std::size_t slotId,
        const std::size_t startIndex,
        const std::size_t endIndex,
        SharedScanState* sharedState)
    {
        auto attempt = std::make_shared<WorkerAttempt>();
        attempt->slotId = slotId;
        attempt->startIndex = startIndex;
        attempt->endIndex = endIndex;
        attempt->progressIndex.store(startIndex);
        attempt->lastAliveTickMs.store(getTickMs());

        {
            std::wstringstream stream;
            stream
                << L"spawn worker attempt"
                << L" slot=" << slotId
                << L" start=" << startIndex
                << L" end=" << endIndex;
            logDebug(stream.str());
        }

        std::thread workerThread(workerThreadProc, attempt, sharedState);
        workerThread.detach();
        return attempt;
    }

    // monitorThreadProc：
    // - The monitoring thread continuously checks 16 shards;
    // - If an active attempt has no heartbeat for over 0.5 seconds, mark it as abandoned.
    // - Then start a new thread to resume scanning from the position 'last progress + 2'.
    void monitorThreadProc(
        std::vector<WorkerSlotState>* slotStateList,
        SharedScanState* sharedState,
        std::atomic<bool>* monitorStopFlag)
    {
        if (slotStateList == nullptr || sharedState == nullptr || monitorStopFlag == nullptr)
        {
            return;
        }

        logDebug(L"monitor start");

        while (!monitorStopFlag->load())
        {
            bool allFinished = true;
            const std::uint64_t kNowTickMs = getTickMs();

            for (WorkerSlotState& slotState : *slotStateList)
            {
                if (slotState.finished)
                {
                    continue;
                }
                allFinished = false;

                if (slotState.activeAttempt == nullptr)
                {
                    slotState.finished = true;
                    std::wstringstream stream;
                    stream
                        << L"slot finished without active attempt"
                        << L" slot=" << slotState.slotId;
                    logDebug(stream.str());
                    continue;
                }

                if (slotState.activeAttempt->completed.load())
                {
                    slotState.finished = true;
                    std::wstringstream stream;
                    stream
                        << L"slot completed"
                        << L" slot=" << slotState.slotId
                        << L" progress=" << slotState.activeAttempt->progressIndex.load();
                    logDebug(stream.str());
                    continue;
                }

                const std::uint64_t kLastAliveTickMs = slotState.activeAttempt->lastAliveTickMs.load();
                if (kNowTickMs <= kLastAliveTickMs || (kNowTickMs - kLastAliveTickMs) <= kHeartbeatTimeoutMs)
                {
                    continue;
                }

                const std::size_t kResumeIndex = slotState.activeAttempt->progressIndex.load() + 2;
                slotState.activeAttempt->abandoned.store(true);
                const std::size_t kRespawnCount = sharedState->timeoutRespawnCount.fetch_add(1) + 1;

                {
                    std::wstringstream stream;
                    stream
                        << L"worker timeout detected"
                        << L" slot=" << slotState.slotId
                        << L" lastAlive=" << kLastAliveTickMs
                        << L" now=" << kNowTickMs
                        << L" progress=" << slotState.activeAttempt->progressIndex.load()
                        << L" resume=" << kResumeIndex
                        << L" respawnCount=" << kRespawnCount;
                    logDebug(stream.str());
                }

                if (kResumeIndex > slotState.rangeEnd)
                {
                    slotState.finished = true;
                    std::wstringstream stream;
                    stream
                        << L"slot timeout but range exhausted"
                        << L" slot=" << slotState.slotId
                        << L" rangeEnd=" << slotState.rangeEnd;
                    logDebug(stream.str());
                    continue;
                }

                slotState.activeAttempt = startAttempt(
                    slotState.slotId,
                    kResumeIndex,
                    slotState.rangeEnd,
                    sharedState);
            }

            if (allFinished)
            {
                monitorStopFlag->store(true);
                logDebug(L"monitor stop: all slots finished");
                return;
            }

            ::Sleep(kMonitorSleepMs);
        }

        logDebug(L"monitor stop: flag set");
    }
}

// ============================================================
// wmain：
// - The main entry point handles input paths, captures handle snapshots, and parses File TypeIndex.
// - Then split the snapshot into 16 segments for worker threads;
// - Wait for the monitoring thread to converge and output results.
// ============================================================
int wmain()
{
    ::SetConsoleOutputCP(CP_UTF8);
    ::SetConsoleCP(CP_UTF8);

    logDebug(L"program start");

    const bool kDebugPrivilegeEnabled = enableDebugPrivilege();
    writeConsoleLine(
        L"SeDebugPrivilege=" + std::wstring(kDebugPrivilegeEnabled ? L"Enabled" : L"Disabled"));
    logDebug(kDebugPrivilegeEnabled ? L"SeDebugPrivilege enabled" : L"SeDebugPrivilege disabled");

    writeConsoleText(L"Input target path: ");
    std::wstring inputPath;
    if (!readConsoleLine(inputPath))
    {
        logDebug(L"readConsoleLine failed");
        writeConsoleLine(L"Read input failed.");
        ::system("pause");
        return 0;
    }
    if (inputPath.empty())
    {
        logDebug(L"input path empty");
        writeConsoleLine(L"Input path is empty.");
        ::system("pause");
        return 0;
    }

    {
        std::wstringstream stream;
        stream << L"input path=" << inputPath;
        logDebug(stream.str());
    }

    const DWORD kFileAttributes = ::GetFileAttributesW(inputPath.c_str());
    if (kFileAttributes == INVALID_FILE_ATTRIBUTES)
    {
        std::wstringstream stream;
        stream << L"GetFileAttributesW failed, error=" << ::GetLastError();
        logDebug(stream.str());
        writeConsoleLine(L"Target path does not exist or is inaccessible.");
        ::system("pause");
        return 0;
    }

    const bool kDirectoryMode = (kFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
    logDebug(kDirectoryMode ? L"target mode=directory" : L"target mode=file");
    UniqueHandle targetHandle;
    if (!openTargetPathHandle(inputPath, kDirectoryMode, targetHandle))
    {
        std::wstringstream stream;
        stream << L"openTargetPathHandle failed, error=" << ::GetLastError();
        logDebug(stream.str());
        writeConsoleLine(L"Target path open failed.");
        ::system("pause");
        return 0;
    }
    logDebug(L"target path opened successfully");
    {
        std::wstringstream stream;
        stream
            << L"target handle value=0x"
            << std::hex << reinterpret_cast<std::uintptr_t>(targetHandle.get());
        logDebug(stream.str());
    }

    std::vector<std::uint8_t> handleBuffer;
    logDebug(L"querySystemHandles begin");
    if (!querySystemHandles(handleBuffer))
    {
        logDebug(L"querySystemHandles failed");
        writeConsoleLine(L"System handle snapshot query failed.");
        ::system("pause");
        return 0;
    }
    {
        std::wstringstream stream;
        stream << L"querySystemHandles success, bufferBytes=" << handleBuffer.size();
        logDebug(stream.str());
    }

    const auto* handleInfo =
        reinterpret_cast<const SYSTEM_HANDLE_INFORMATION_NATIVE*>(handleBuffer.data());
    if (handleInfo == nullptr || handleInfo->handleCount == 0)
    {
        logDebug(L"handle snapshot empty");
        writeConsoleLine(L"System handle snapshot is empty.");
        ::system("pause");
        return 0;
    }
    {
        std::wstringstream stream;
        stream << L"snapshot handle count=" << static_cast<std::size_t>(handleInfo->handleCount);
        logDebug(stream.str());
    }

    std::uint8_t fileTypeIndex = 0;
    if (!resolveFileTypeIndex(targetHandle.get(), handleInfo, fileTypeIndex))
    {
        logDebug(L"resolveFileTypeIndex failed");
        writeConsoleLine(L"Resolve File TypeIndex failed.");
        ::system("pause");
        return 0;
    }
    {
        std::wstringstream stream;
        stream << L"resolved FileTypeIndex=" << static_cast<unsigned int>(fileTypeIndex);
        logDebug(stream.str());
    }

    SharedScanState sharedState{};
    sharedState.handleInfo = handleInfo;
    sharedState.handleCount = handleInfo->handleCount;
    sharedState.fileTypeIndex = fileTypeIndex;
    sharedState.directoryMode = kDirectoryMode;
    sharedState.normalizedTargetPath = normalizePathForCompare(inputPath);
    sharedState.processNameMap = getProcessNameMap();
    sharedState.emittedHandleKeySet.reserve(512);
    sharedState.matchList.reserve(128);

    {
        std::wstringstream stream;
        stream
            << L"snapshot handle count=" << handleInfo->handleCount
            << L", FileTypeIndex=" << static_cast<unsigned int>(fileTypeIndex)
            << L", WorkerCount=" << kWorkerCount;
        writeConsoleLine(stream.str());
    }

    std::vector<WorkerSlotState> slotStateList;
    slotStateList.reserve(kWorkerCount);
    const std::size_t kTotalHandleCount = static_cast<std::size_t>(handleInfo->handleCount);
    const std::size_t kChunkSize = (kTotalHandleCount + kWorkerCount - 1) / kWorkerCount;
    {
        std::wstringstream stream;
        stream
            << L"prepare slots"
            << L" totalHandleCount=" << kTotalHandleCount
            << L" chunkSize=" << kChunkSize;
        logDebug(stream.str());
    }

    for (std::size_t slotId = 0; slotId < kWorkerCount; ++slotId)
    {
        const std::size_t kRangeBegin = slotId * kChunkSize;
        if (kRangeBegin >= kTotalHandleCount)
        {
            break;
        }

        const std::size_t kRangeEnd = std::min(kTotalHandleCount, kRangeBegin + kChunkSize) - 1;
        WorkerSlotState slotState{};
        slotState.slotId = slotId;
        slotState.rangeBegin = kRangeBegin;
        slotState.rangeEnd = kRangeEnd;
        slotState.activeAttempt = startAttempt(slotId, kRangeBegin, kRangeEnd, &sharedState);
        slotStateList.push_back(std::move(slotState));
    }

    std::atomic<bool> monitorStopFlag = false;
    std::thread monitorThread(monitorThreadProc, &slotStateList, &sharedState, &monitorStopFlag);
    monitorThread.join();
    logDebug(L"monitor joined");

    {
        std::lock_guard<std::mutex> lock(sharedState.resultMutex);
        std::sort(
            sharedState.matchList.begin(),
            sharedState.matchList.end(),
            [](const MatchRecord& leftRecord, const MatchRecord& rightRecord)
            {
                if (leftRecord.processId != rightRecord.processId)
                {
                    return leftRecord.processId < rightRecord.processId;
                }
                if (leftRecord.handleValue != rightRecord.handleValue)
                {
                    return leftRecord.handleValue < rightRecord.handleValue;
                }
                return leftRecord.sourceIndex < rightRecord.sourceIndex;
            });

        for (const MatchRecord& record : sharedState.matchList)
        {
            std::wcout
                << L"Handle[" << record.sourceIndex << L"] "
                << L"PID=" << record.processId
                << L" Name=" << record.processName
                << L" Handle=0x" << std::hex << record.handleValue << std::dec
                << L" Path=" << record.finalPath
                << std::endl;
        }
    }

    {
        std::wstringstream stream;
        stream
            << L"scan done, matched=" << sharedState.matchList.size()
            << L", openProcessFail=" << sharedState.openProcessFailedCount.load()
            << L", duplicateFail=" << sharedState.duplicateFailedCount.load()
            << L", pathFail=" << sharedState.pathQueryFailedCount.load()
            << L", nonDiskSkip=" << sharedState.nonDiskFileSkippedCount.load()
            << L", timeoutRespawn=" << sharedState.timeoutRespawnCount.load();
        writeConsoleLine(stream.str());
    }
    logDebug(L"program end");

    ::system("pause");
    return 0;
}

#include "Process.h"
#include "ProcessCpuUsageModel.h"

#include "../string/String.h"

// Win32 headers: processes, threads, tokens, tool snapshots, shells, signatures, etc.
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <Psapi.h>
#include <TlHelp32.h>
#include <WinTrust.h>
#include <Softpub.h>
#include <wincrypt.h>
#include <Shellapi.h>
#include <winternl.h>
#include <RestartManager.h>
#include <pdh.h>
#include <pdhmsg.h>
#include <ShellScalingApi.h> // PROCESS_DPI_AWARENESS: Fallback query type for DPI awareness when the user32 path is unavailable.
#include <appmodel.h>        // APPMODEL_ERROR_NO_PACKAGE: Distinguish between 'process does not belong to any package' and a genuine query failure.

#include <algorithm>   // std::max/std::clamp: Derived metric calculation.
#include <chrono>      // steady_clock: timing across refresh cycles.
#include <cmath>       // std::isfinite: Filter out abnormal floating-point values returned by PDH.
#include <cstddef>     // offsetof: Validates the variable-length system handle table buffer.
#include <cstring>     // std::memset: zeroing the output buffer before reading the remote structure.
#include <cwchar>      // std::swprintf/std::wcstoul: Concatenate version info path and parse PDH PID.
#include <cwctype>     // std::towlower: Normalizes case when parsing GPU Engine instance names.
#include <filesystem>  // std::filesystem: Path existence and directory judgment.
#include <fstream>     // std::ifstream: Reads PE header to calculate entry RVA.
#include <iomanip>     // std::hex: Format hexadecimal text.
#include <iterator>    // std::size: Static array length.
#include <limits>      // std::numeric_limits: Numeric boundary check.
#include <mutex>       // std::mutex: Protect the global PDH query handle.
#include <new>         // std::nothrow: remote injection defers context cleanup; allocation failure does not throw an exception.
#include <sstream>     // std::ostringstream: concatenating error text.
#include <string>      // std::string/std::wstring: Process text and PDH instance name.
#include <unordered_map> // std::unordered_map: Cache PID->process name during thread enumeration.
#include <utility>     // std::move: Avoid extra copies when writing records to the container.
#include <vector>      // std::vector: System information buffer and container.

// Linked dependency libraries:
// - Psapi：GetProcessMemoryInfo；
// - Wintrust/Crypt32: Digital signature verification.
// - Version: Read CompanyName from the file version information (fallback manufacturer).
// - Pdh: Reads Windows GPU Engine performance counters to complete per-process GPU utilization.
#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "Wintrust.lib")
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "Version.lib")
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Pdh.lib")
// - User32: GetGuiResources is used for the GDI/User Object count columns to align with Task Manager.
#pragma comment(lib, "User32.lib")

namespace
{
    // STATUS_INFO_LENGTH_MISMATCH: Return code for buffer too small from NtQuerySystemInformation.
#ifndef STATUS_INFO_LENGTH_MISMATCH
    constexpr NTSTATUS kStatusInfoLengthMismatch = static_cast<NTSTATUS>(0xC0000004L);
#else
    constexpr NTSTATUS StatusInfoLengthMismatch = STATUS_INFO_LENGTH_MISMATCH;
#endif

    // PROCESS_SUSPEND_RESUME: older headers may not define it; provide a manual fallback.
#ifndef PROCESS_SUSPEND_RESUME
    constexpr DWORD ProcessSuspendResumeAccess = 0x0800;
#else
    constexpr DWORD kProcessSuspendResumeAccess = PROCESS_SUSPEND_RESUME;
#endif

    // ProcessBreakOnTermination: a key process information class for NtSetInformationProcess.
    constexpr PROCESSINFOCLASS kProcessBreakOnTerminationInfoClass = static_cast<PROCESSINFOCLASS>(29);

    // ProcessPowerThrottling: Efficiency mode information class for Get/SetProcessInformation.
    constexpr ULONG kProcessPowerThrottlingInfoClass = 4UL;
    constexpr ULONG kProcessPowerThrottlingCurrentVersion = 1UL;
    constexpr ULONG kProcessPowerThrottlingExecutionSpeed = 0x1UL;

    // ProcessProtectionLevelInfo：
    // - GetProcessInformation PROCESS_INFORMATION_CLASS enumeration value 7.
    // - Returns PROCESS_PROTECTION_LEVEL_INFORMATION.ProtectionLevel.
    constexpr ULONG kProcessProtectionLevelInfoClass = 7UL;

    // PROTECTION_LEVEL_*：
    // - Some build environments do not expose these macros in processthreadsapi.h;
    // - Local fallback values are used solely for decoding the public enumeration from GetProcessInformation.
    // - 0 is also used for WINTCB_LIGHT; naming follows the public macros in WinBase.h for consistency.
    constexpr DWORD kProcessProtectionLevelWinTcbLight = 0x00000000UL;
    constexpr DWORD kProcessProtectionLevelNone = 0xFFFFFFFEUL;
    constexpr DWORD kProcessProtectionLevelWindows = 0x00000001UL;
    constexpr DWORD kProcessProtectionLevelWindowsLight = 0x00000002UL;
    constexpr DWORD kProcessProtectionLevelAntimalwareLight = 0x00000003UL;
    constexpr DWORD kProcessProtectionLevelLsaLight = 0x00000004UL;
    constexpr DWORD kProcessProtectionLevelWinTcb = 0x00000005UL;
    constexpr DWORD kProcessProtectionLevelCodegenLight = 0x00000006UL;
    constexpr DWORD kProcessProtectionLevelAuthenticode = 0x00000007UL;
    constexpr DWORD kProcessProtectionLevelPplApp = 0x00000008UL;
    constexpr DWORD kProcessProtectionLevelSame = 0xFFFFFFFFUL;

    // Restart Manager shutdown flag:
    // - Use local constants uniformly here instead of directly relying on whether the SDK exposes enumeration names.
    // - Semantically equivalent to the Restart Manager's force shutdown option.
    constexpr ULONG kRestartManagerForceShutdownFlag = 0x1UL;

    // NT_SUCCESS: Determines whether NTSTATUS indicates success.
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

    // Nt function pointer type definitions.
    using NtQuerySystemInformationFn = NTSTATUS(NTAPI*)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);
    using NtQueryInformationProcessFn = NTSTATUS(NTAPI*)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
    using GetProcessInformationFn = BOOL(WINAPI*)(HANDLE, ULONG, LPVOID, DWORD);
    using SetProcessInformationFn = BOOL(WINAPI*)(HANDLE, ULONG, LPVOID, DWORD);
    using NtSuspendProcessFn = NTSTATUS(NTAPI*)(HANDLE);
    using NtResumeProcessFn = NTSTATUS(NTAPI*)(HANDLE);
    using NtSetInformationProcessFn = NTSTATUS(NTAPI*)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG);
    using NtTerminateProcessFn = NTSTATUS(NTAPI*)(HANDLE, NTSTATUS);
    using NtTerminateThreadFn = NTSTATUS(NTAPI*)(HANDLE, NTSTATUS);
    using NtTerminateJobObjectFn = NTSTATUS(NTAPI*)(HANDLE, NTSTATUS);
    using NtUnmapViewOfSectionFn = NTSTATUS(NTAPI*)(HANDLE, PVOID);
    using PdhAddEnglishCounterWFn = PDH_STATUS(WINAPI*)(HQUERY, LPCWSTR, DWORD_PTR, HCOUNTER*);

    // ProcessBasicInformation result structure (corresponding to NtQueryInformationProcess).
    struct ProcessBasicInformationLocal
    {
        PVOID reserved1 = nullptr;
        PVOID pebBaseAddress = nullptr;
        PVOID reserved2[2]{};
        ULONG_PTR uniqueProcessId = 0;
        PVOID reserved3 = nullptr;
    };

    // ProcessCommandLineInformation：
    // - NtQueryInformationProcess information class 60.
    // - Prioritizing this path avoids manual PEB offset differences.
    constexpr PROCESSINFOCLASS kProcessCommandLineInformationClass =
        static_cast<PROCESSINFOCLASS>(60);

    // ProcessWow64Information：
    // - NtQueryInformationProcess information class 26.
    // - Used to retrieve the Wow64 PEB address when a 64-bit tool reads a 32-bit target.
    constexpr PROCESSINFOCLASS kProcessWow64InformationClass =
        static_cast<PROCESSINFOCLASS>(26);

    // Maximum read length for remote UNICODE_STRING:
    // - Length comes from the target process memory and cannot be trusted unconditionally;
    // - 256KB is sufficient to cover normal command lines while preventing oversized allocations due to bad pointers.
    constexpr std::size_t kRemoteUnicodeStringMaxBytes = 256 * 1024;

    // RemoteUnicodeString32：
    // - The actual layout of UNICODE_STRING within a 32-bit target process;
    // - Buffer is a 32-bit remote address; it must be promoted to a 64-bit integer before reading.
    struct RemoteUnicodeString32
    {
        USHORT length = 0;        // String byte count, excluding the terminating NUL.
        USHORT maximumLength = 0; // Buffer capacity in bytes.
        std::uint32_t buffer = 0; // 32-bit remote PWSTR address.
    };

    // Peb32CommandLineLite / Peb64CommandLineLite：
    // - Retain only the PEB starting fields up to ProcessParameters.
    // - Avoid relying on the SDK-truncated PEB and avoid reading the entire PEB structure.
    struct Peb32CommandLineLite
    {
        BYTE reserved1[2]{};
        BYTE beingDebugged = 0;
        BYTE reserved2[1]{};
        std::uint32_t mutant = 0;
        std::uint32_t imageBaseAddress = 0;
        std::uint32_t ldr = 0;
        std::uint32_t processParameters = 0;
    };

    struct Peb64CommandLineLite
    {
        BYTE reserved1[2]{};
        BYTE beingDebugged = 0;
        BYTE reserved2[1]{};
        PVOID mutant = nullptr;
        PVOID imageBaseAddress = nullptr;
        PVOID ldr = nullptr;
        PVOID processParameters = nullptr;
    };

    // RtlUserProcessParameters32CommandLine / 64CommandLine：
    // - Locate the CommandLine field directly using public stable offsets.
    // - 32-bit CommandLine is at offset 0x40; 64-bit CommandLine is at offset 0x70.
    struct RtlUserProcessParameters32CommandLine
    {
        BYTE reservedBeforeCommandLine[0x40]{};
        RemoteUnicodeString32 commandLine{};
    };

    struct RtlUserProcessParameters64CommandLine
    {
        BYTE reservedBeforeCommandLine[0x70]{};
        UNICODE_STRING commandLine{};
    };

    // Complete structure definition for NtQuerySystemInformation(SystemProcessInformation).
    // Notes:
    // - Some SDKs truncate the _SYSTEM_PROCESS_INFORMATION fields;
    // - Uses a compatible definition to read creation time, CPU time, and I/O counters.
    struct SystemProcessInformationRecord
    {
        ULONG nextEntryOffset;
        ULONG numberOfThreads;
        LARGE_INTEGER workingSetPrivateSize;
        ULONG hardFaultCount;
        ULONG numberOfThreadsHighWatermark;
        ULONGLONG cycleTime;
        LARGE_INTEGER createTime;
        LARGE_INTEGER userTime;
        LARGE_INTEGER kernelTime;
        UNICODE_STRING imageName;
        LONG basePriority;
        HANDLE uniqueProcessId;
        HANDLE inheritedFromUniqueProcessId;
        ULONG handleCount;
        ULONG sessionId;
        ULONG_PTR uniqueProcessKey;
        SIZE_T peakVirtualSize;
        SIZE_T virtualSize;
        ULONG pageFaultCount;
        SIZE_T peakWorkingSetSize;
        SIZE_T workingSetSize;
        SIZE_T quotaPeakPagedPoolUsage;
        SIZE_T quotaPagedPoolUsage;
        SIZE_T quotaPeakNonPagedPoolUsage;
        SIZE_T quotaNonPagedPoolUsage;
        SIZE_T pagefileUsage;
        SIZE_T peakPagefileUsage;
        SIZE_T privatePageCount;
        LARGE_INTEGER readOperationCount;
        LARGE_INTEGER writeOperationCount;
        LARGE_INTEGER otherOperationCount;
        LARGE_INTEGER readTransferCount;
        LARGE_INTEGER writeTransferCount;
        LARGE_INTEGER otherTransferCount;
    };

    // Thread sub-structure within NtQuerySystemInformation(SystemProcessInformation).
    // Notes:
    // - Official winternl headers have field naming differences across different SDKs;
    // - Uses compatible layout to ensure readable core thread fields (TID, priority, status, etc.).
    struct SystemThreadInformationRecord
    {
        LARGE_INTEGER reservedTime[3];  // [0]=KernelTime, [1]=UserTime, [2]=CreateTime。
        ULONG waitTime;                 // Thread wait duration counter (raw value).
        PVOID startAddress;             // Thread start address.
        CLIENT_ID clientId;             // Thread and its owning process identifier.
        KPRIORITY priority;             // Current dynamic priority
        LONG basePriority;              // Base priority.
        ULONG contextSwitches;          // Context switch count.
        ULONG threadState;              // Thread state code (KTHREAD_STATE).
        ULONG waitReason;               // Wait reason code (KWAIT_REASON).
    };

    // SystemExtendedThreadInformationRecord：
    // - Thread record extended layout for SystemExtendedProcessInformation(57).
    // - Provides StackBase, StackLimit, Win32StartAddress, and
    //   TebBaseAddress in addition to the base SystemThreadInformation.
    // - These fields belong to the public NtQuery return data and do not depend on R0 drivers.
    struct SystemExtendedThreadInformationRecord
    {
        SystemThreadInformationRecord threadInfo{};
        PVOID stackBase = nullptr;
        PVOID stackLimit = nullptr;
        PVOID win32StartAddress = nullptr;
        PVOID tebBaseAddress = nullptr;
        ULONG_PTR reserved2 = 0;
        ULONG_PTR reserved3 = 0;
        ULONG_PTR reserved4 = 0;
    };

    // SystemHandleTableEntryInfoExLocal：
    // - A single handle record from SystemExtendedHandleInformation(64);
    // - Used to aggregate handle counts by PID directly in R3, avoiding dependency on the target process being openable.
    struct SystemHandleTableEntryInfoExLocal
    {
        PVOID objectAddress = nullptr;          // objectAddress: Kernel object address; not used by this function.
        ULONG_PTR uniqueProcessId = 0;          // uniqueProcessId: PID to which the handle belongs.
        ULONG_PTR handleValue = 0;              // handleValue: handle value; not used by this function.
        ULONG grantedAccess = 0;                // grantedAccess: Access mask; not used by this function.
        USHORT creatorBackTraceIndex = 0;       // creatorBackTraceIndex: Creation stack index; unused in this function.
        USHORT objectTypeIndex = 0;             // objectTypeIndex: object type index; unused by this function.
        ULONG handleAttributes = 0;             // handleAttributes: Handle attributes; unused in this function.
        ULONG reserved = 0;                     // reserved: Reserved field.
    };

    // SystemHandleInformationExLocal：
    // - Buffer header for SystemExtendedHandleInformation(64);
    // - handles: Variable-length array; must be double-validated against buffer size before access.
    struct SystemHandleInformationExLocal
    {
        ULONG_PTR numberOfHandles = 0;                    // numberOfHandles: The total number of system handles.
        ULONG_PTR reserved = 0;                           // reserved: Reserved field.
        SystemHandleTableEntryInfoExLocal handles[1] = {}; // handles: First element of a variable-length handle array.
    };

    // Thread state and wait reason constants:
    // - KTHREAD_STATE::Waiting = 5；
    // - KWAIT_REASON::Suspended = 5，WrSuspended = 12；
    // - Task Manager displays a process as 'Suspended' when all its threads are in a suspended wait state.
    constexpr ULONG kSystemThreadStateWaiting = 5UL;
    constexpr ULONG kSystemThreadWaitReasonSuspended = 5UL;
    constexpr ULONG kSystemThreadWaitReasonWrSuspended = 12UL;

    // applyProcessSuspendedStateFromThreadArray:
    // - Input: A single process record from the SystemProcessInformation buffer and its thread count;
    // - Processing: Iterate through the thread array immediately following the process record and count threads in a suspended state.
    // - Return: No return value; the result is written directly back to processRecord.
    // Bounds protection: The thread array must be entirely within the buffer; otherwise, discard the judgment and keep processStateKnown = false.
    void applyProcessSuspendedStateFromThreadArray(
        ks::process::ProcessRecord& processRecord,
        const BYTE* const processEntryPointer,
        const BYTE* const bufferBegin,
        const std::size_t bufferSize,
        const std::uint32_t threadCount)
    {
        processRecord.suspendedThreadCount = 0;
        processRecord.processSuspended = false;
        processRecord.processStateKnown = false;

        if (processEntryPointer == nullptr || bufferBegin == nullptr || bufferSize == 0)
        {
            return;
        }
        if (threadCount == 0)
        {
            // Process records without thread information (e.g., Idle summary items) are treated as 'running' to avoid being incorrectly displayed as suspended.
            processRecord.processStateKnown = true;
            return;
        }

        const BYTE* const kThreadArrayBegin = processEntryPointer + sizeof(SystemProcessInformationRecord);
        if (kThreadArrayBegin < bufferBegin)
        {
            return;
        }

        const std::size_t kConsumedBytes = static_cast<std::size_t>(kThreadArrayBegin - bufferBegin);
        const std::size_t kThreadArrayBytes =
            static_cast<std::size_t>(threadCount) * sizeof(SystemThreadInformationRecord);
        if (kConsumedBytes > bufferSize || kThreadArrayBytes > (bufferSize - kConsumedBytes))
        {
            return;
        }

        const auto* const kThreadArray =
            reinterpret_cast<const SystemThreadInformationRecord*>(kThreadArrayBegin);
        std::uint32_t suspendedCount = 0;
        for (std::uint32_t threadIndex = 0; threadIndex < threadCount; ++threadIndex)
        {
            const SystemThreadInformationRecord& threadInfo = kThreadArray[threadIndex];
            if (threadInfo.threadState != kSystemThreadStateWaiting)
            {
                continue;
            }
            if (threadInfo.waitReason == kSystemThreadWaitReasonSuspended ||
                threadInfo.waitReason == kSystemThreadWaitReasonWrSuspended)
            {
                ++suspendedCount;
            }
        }

        processRecord.suspendedThreadCount = suspendedCount;
        processRecord.processSuspended = (suspendedCount == threadCount);
        processRecord.processStateKnown = true;
    }

    // Format Win32 error code text for UI display to provide detailed failure reasons.
    std::string formatLastErrorMessage(const DWORD errorCode)
    {
        wchar_t* wideBuffer = nullptr;
        const DWORD kMessageLength = ::FormatMessageW(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            nullptr,
            errorCode,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            reinterpret_cast<LPWSTR>(&wideBuffer),
            0,
            nullptr);

        if (kMessageLength == 0 || wideBuffer == nullptr)
        {
            std::ostringstream stream;
            stream << "Win32Error=" << errorCode;
            return stream.str();
        }

        std::wstring wideMessage(wideBuffer, kMessageLength);
        ::LocalFree(wideBuffer);

        std::string utf8Message = ks::str::utf16ToUtf8(wideMessage);
        utf8Message = ks::str::trimCopy(utf8Message);

        std::ostringstream stream;
        stream << utf8Message << " (Code=" << errorCode << ")";
        return stream.str();
    }

    // Format NTSTATUS to avoid the UI only seeing 'failure' without the specific error code value.
    std::string formatNtStatusMessage(const NTSTATUS statusCode, const char* prefixText)
    {
        std::ostringstream stream;
        stream << (prefixText == nullptr ? "NTSTATUS failed" : prefixText)
            << " (0x" << std::hex << static_cast<unsigned long>(statusCode) << ")";
        return stream.str();
    }

    // Get the address of a specified exported function in ntdll (lazy loading).
    FARPROC getNtdllProcAddress(const char* functionName)
    {
        HMODULE ntdllModule = ::GetModuleHandleW(L"ntdll.dll");
        if (ntdllModule == nullptr)
        {
            ntdllModule = ::LoadLibraryW(L"ntdll.dll");
        }
        if (ntdllModule == nullptr)
        {
            return nullptr;
        }
        return ::GetProcAddress(ntdllModule, functionName);
    }

    // ProcessBasicInformationFullLocal：
    // - The publicly exposed PROCESS_BASIC_INFORMATION in winternl.h hides BasePriority within the Reserved field.
    // - Using the full layout here is solely to read the KPRIORITY required for the Task Manager's 'Base Priority' column.
    struct ProcessBasicInformationFullLocal
    {
        NTSTATUS exitStatus = 0;                       // Process exit code.
        PVOID pebBaseAddress = nullptr;                // PEB base address; not used for this purpose.
        ULONG_PTR affinityMask = 0;                    // Affinity mask; not used for this purpose.
        LONG basePriority = 0;                         // KPRIORITY: Base priority ranging from 0 to 31.
        ULONG_PTR uniqueProcessId = 0;                 // PID。
        ULONG_PTR inheritedFromUniqueProcessId = 0;    // Parent process PID.
    };

    // applyProcessBasePriorityAndCycleTimeByHandle:
    // - Input: Opened process handle (at least PROCESS_QUERY_LIMITED_INFORMATION permissions);
    // - Processing: Read KPRIORITY base priority and cumulative CPU cycle count.
    // - Returns: None. On failure, retains the original values in the record and keeps cycleTimeKnown as false.
    // Note: This function is used only in non-NtQuery enumeration paths; the NtQuery path already retrieves the same values in the enumeration buffer.
    void applyProcessBasePriorityAndCycleTimeByHandle(
        ks::process::ProcessRecord& processRecord,
        const HANDLE processHandle)
    {
        if (processHandle == nullptr || processHandle == INVALID_HANDLE_VALUE)
        {
            return;
        }

        const auto kNtQueryInformationProcess = reinterpret_cast<NtQueryInformationProcessFn>(
            getNtdllProcAddress("NtQueryInformationProcess"));
        if (kNtQueryInformationProcess != nullptr)
        {
            ProcessBasicInformationFullLocal basicInfo{};
            ULONG returnLength = 0;
            const NTSTATUS kQueryStatus = kNtQueryInformationProcess(
                processHandle,
                ProcessBasicInformation,
                &basicInfo,
                static_cast<ULONG>(sizeof(basicInfo)),
                &returnLength);
            if (NT_SUCCESS(kQueryStatus) && returnLength >= sizeof(basicInfo))
            {
                processRecord.basePriority = static_cast<std::int32_t>(basicInfo.basePriority);
            }
        }

        // QueryProcessCycleTime is declared in realtimeapiset.h, but default inclusion varies across SDKs.
        // Therefore, we uniformly resolve the kernel32 export dynamically to avoid compile-time dependencies.
        using QueryProcessCycleTimeFn = BOOL(WINAPI*)(HANDLE, PULONG64);
        HMODULE kernel32Module = ::GetModuleHandleW(L"kernel32.dll");
        const auto kQueryProcessCycleTime = reinterpret_cast<QueryProcessCycleTimeFn>(
            kernel32Module != nullptr ? ::GetProcAddress(kernel32Module, "QueryProcessCycleTime") : nullptr);
        if (kQueryProcessCycleTime != nullptr)
        {
            ULONG64 cycleTimeValue = 0;
            if (kQueryProcessCycleTime(processHandle, &cycleTimeValue) != FALSE)
            {
                processRecord.cycleTime = static_cast<std::uint64_t>(cycleTimeValue);
                processRecord.cycleTimeKnown = true;
            }
        }
    }

    // Query whether a privilege (e.g., SeDebug) can be elevated, used for high-privilege operations on critical processes.
    bool enablePrivilege(const wchar_t* privilegeName)
    {
        if (privilegeName == nullptr)
        {
            return false;
        }

        HANDLE processToken = nullptr;
        if (::OpenProcessToken(::GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &processToken) == FALSE)
        {
            return false;
        }

        LUID privilegeLuid{};
        if (::LookupPrivilegeValueW(nullptr, privilegeName, &privilegeLuid) == FALSE)
        {
            ::CloseHandle(processToken);
            return false;
        }

        TOKEN_PRIVILEGES tokenPrivileges{};
        tokenPrivileges.PrivilegeCount = 1;
        tokenPrivileges.Privileges[0].Luid = privilegeLuid;
        tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        const BOOL kAdjustResult = ::AdjustTokenPrivileges(
            processToken,
            FALSE,
            &tokenPrivileges,
            sizeof(tokenPrivileges),
            nullptr,
            nullptr);
        const DWORD kAdjustError = ::GetLastError();
        ::CloseHandle(processToken);

        return kAdjustResult != FALSE && kAdjustError == ERROR_SUCCESS;
    }

    // queryProcessHandleCountsBySystemSnapshot:
    // - Reuse the same approach as the handle module: obtain a full-system handle snapshot via NtQuerySystemInformation(64).
    // - Aggregate handle counts per PID by uniqueProcessId;
    // - This path does not require opening the target process, so it can provide R3-perceivable handle counts for PPL/high-privilege processes.
    std::unordered_map<std::uint32_t, std::uint32_t> queryProcessHandleCountsBySystemSnapshot()
    {
        std::unordered_map<std::uint32_t, std::uint32_t> handleCountByPid;

        const auto kNtQuerySystemInformation = reinterpret_cast<NtQuerySystemInformationFn>(
            getNtdllProcAddress("NtQuerySystemInformation"));
        if (kNtQuerySystemInformation == nullptr)
        {
            return handleCountByPid;
        }

        const SYSTEM_INFORMATION_CLASS kSystemExtendedHandleInformation =
            static_cast<SYSTEM_INFORMATION_CLASS>(64);
        constexpr NTSTATUS kStatusBufferOverflow = static_cast<NTSTATUS>(0x80000005L);
        constexpr NTSTATUS kStatusBufferTooSmall = static_cast<NTSTATUS>(0xC0000023L);
        constexpr ULONG kMaxBufferLength = 256UL * 1024UL * 1024UL;
        ULONG bufferLength = 2UL * 1024UL * 1024UL;
        ULONG returnLength = 0;
        std::vector<BYTE> informationBuffer(bufferLength);

        NTSTATUS queryStatus = kNtQuerySystemInformation(
            kSystemExtendedHandleInformation,
            informationBuffer.data(),
            bufferLength,
            &returnLength);

        while (queryStatus == kStatusInfoLengthMismatch ||
            queryStatus == kStatusBufferOverflow ||
            queryStatus == kStatusBufferTooSmall)
        {
            ULONG nextLength = (returnLength > bufferLength)
                ? returnLength
                : (bufferLength + bufferLength / 2UL + 64UL * 1024UL);
            if (nextLength <= bufferLength || nextLength > kMaxBufferLength)
            {
                return handleCountByPid;
            }

            bufferLength = nextLength;
            informationBuffer.assign(bufferLength, 0);
            returnLength = 0;
            queryStatus = kNtQuerySystemInformation(
                kSystemExtendedHandleInformation,
                informationBuffer.data(),
                bufferLength,
                &returnLength);
        }

        if (!NT_SUCCESS(queryStatus) ||
            informationBuffer.size() < sizeof(SystemHandleInformationExLocal))
        {
            return handleCountByPid;
        }

        const auto* handleInfo =
            reinterpret_cast<const SystemHandleInformationExLocal*>(informationBuffer.data());
        const std::size_t kHeaderBytes =
            offsetof(SystemHandleInformationExLocal, handles);
        const std::size_t kAvailableEntryBytes =
            informationBuffer.size() > kHeaderBytes ? informationBuffer.size() - kHeaderBytes : 0;
        const std::size_t kSafeHandleCount = std::min<std::size_t>(
            static_cast<std::size_t>(handleInfo->numberOfHandles),
            kAvailableEntryBytes / sizeof(SystemHandleTableEntryInfoExLocal));

        handleCountByPid.reserve(std::min<std::size_t>(kSafeHandleCount, 8192));
        for (std::size_t handleIndex = 0; handleIndex < kSafeHandleCount; ++handleIndex)
        {
            const auto& handleEntry = handleInfo->handles[handleIndex];
            const std::uint32_t kProcessId = static_cast<std::uint32_t>(handleEntry.uniqueProcessId);
            ++handleCountByPid[kProcessId];
        }

        return handleCountByPid;
    }

    // containsGpuEnginePidPrefixAt:
    // - Check if the position in the GPU Engine instance name is "pid_";
    // - PDH instance names are typically in the format pid_1234_luid_..._engtype_3D.
    // - Case-insensitive matching is used here to avoid case differences in output across different Windows builds.
    bool containsGpuEnginePidPrefixAt(
        const std::wstring& instanceName,
        const std::size_t offset)
    {
        constexpr wchar_t kExpectedPrefix[] = L"pid_";
        constexpr std::size_t kExpectedPrefixLength = 4;
        if (offset + kExpectedPrefixLength > instanceName.size())
        {
            return false;
        }

        for (std::size_t prefixIndex = 0; prefixIndex < kExpectedPrefixLength; ++prefixIndex)
        {
            const wchar_t kActualChar = static_cast<wchar_t>(
                std::towlower(instanceName[offset + prefixIndex]));
            if (kActualChar != kExpectedPrefix[prefixIndex])
            {
                return false;
            }
        }
        return true;
    }

    // extractPidFromGpuEngineInstanceName:
    // - Parses the decimal PID following 'pid_' from the PDH GPU Engine instance name.
    // - Returns 0 if the instance name contains no usable PID; the caller will ignore this counter.
    std::uint32_t extractPidFromGpuEngineInstanceName(const wchar_t* const rawInstanceName)
    {
        if (rawInstanceName == nullptr || rawInstanceName[0] == L'\0')
        {
            return 0;
        }

        const std::wstring kInstanceName(rawInstanceName);
        for (std::size_t offset = 0; offset < kInstanceName.size(); ++offset)
        {
            if (!containsGpuEnginePidPrefixAt(kInstanceName, offset))
            {
                continue;
            }

            const wchar_t* const kDigitBegin = kInstanceName.c_str() + offset + 4;
            if (*kDigitBegin == L'\0' || std::iswdigit(*kDigitBegin) == 0)
            {
                continue;
            }

            wchar_t* digitEnd = nullptr;
            const unsigned long kParsedPid = std::wcstoul(kDigitBegin, &digitEnd, 10);
            if (digitEnd == kDigitBegin || kParsedPid == 0UL)
            {
                continue;
            }
            if (kParsedPid > static_cast<unsigned long>(std::numeric_limits<std::uint32_t>::max()))
            {
                continue;
            }
            return static_cast<std::uint32_t>(kParsedPid);
        }

        return 0;
    }

    // extractGpuEngineDisplayText:
    // - Input: PDH GPU Engine instance name, formatted as
    //   "pid_1234_luid_0x00000000_0x0000A1B2_phys_0_eng_3_engtype_3D"；
    // - Processing: Parse the phys_N and engtype_XXX segments, then combine them into "GPU N - XXX" format identical to Task Manager.
    // - Returns: Display text; returns an empty string if the instance name lacks parsable segments, allowing the caller to skip it.
    std::string extractGpuEngineDisplayText(const wchar_t* const rawInstanceName)
    {
        if (rawInstanceName == nullptr || rawInstanceName[0] == L'\0')
        {
            return std::string();
        }

        // Instance names are entirely ASCII; perform a lowercase normalization first to simplify subsequent lookups.
        std::wstring instanceName(rawInstanceName);
        std::wstring loweredName;
        loweredName.reserve(instanceName.size());
        for (const wchar_t kNameChar : instanceName)
        {
            loweredName.push_back(static_cast<wchar_t>(std::towlower(kNameChar)));
        }

        // Engine type: from 'engtype_' to the end of the string (PDH places it at the end of the instance name).
        std::string engineTypeText;
        const std::size_t kEngineTypeOffset = loweredName.rfind(L"engtype_");
        if (kEngineTypeOffset != std::wstring::npos)
        {
            const std::size_t kValueOffset = kEngineTypeOffset + 8U;
            if (kValueOffset < instanceName.size())
            {
                engineTypeText = ks::str::utf16ToUtf8(instanceName.substr(kValueOffset));
            }
        }
        if (engineTypeText.empty())
        {
            return std::string();
        }

        // Adapter index: the decimal number following 'phys_'; if missing, only the engine type is displayed.
        const std::size_t kPhysicalOffset = loweredName.rfind(L"phys_");
        if (kPhysicalOffset == std::wstring::npos)
        {
            return engineTypeText;
        }

        const wchar_t* const kDigitBegin = instanceName.c_str() + kPhysicalOffset + 5U;
        if (*kDigitBegin == L'\0' || std::iswdigit(*kDigitBegin) == 0)
        {
            return engineTypeText;
        }

        wchar_t* digitEnd = nullptr;
        const unsigned long kPhysicalIndex = std::wcstoul(kDigitBegin, &digitEnd, 10);
        if (digitEnd == kDigitBegin)
        {
            return engineTypeText;
        }

        return std::string("GPU ") + std::to_string(kPhysicalIndex) + " - " + engineTypeText;
    }

    // GpuProcessUsageSample: GPU usage summary for a single process during one PDH sampling round.
    struct GpuProcessUsageSample
    {
        double utilizationPercent = 0.0; // utilizationPercent: The total GPU usage of all engines for this process.
        double topEnginePercent = 0.0;   // topEnginePercent: Percentage of the single engine with the highest usage.
        std::string topEngineText;       // topEngineText: Display name of the engine with the highest usage, e.g., "GPU 0 - 3D".
    };

    // GpuProcessMemorySample: GPU memory usage of a single process during one PDH sampling round.
    struct GpuProcessMemorySample
    {
        std::uint64_t dedicatedBytes = 0; // dedicatedBytes: Dedicated GPU memory in bytes.
        std::uint64_t sharedBytes = 0;    // sharedBytes: Number of bytes in shared GPU memory.
    };

    // GpuPdhQueryState: holds a PDH query object reused across refresh cycles.
    struct GpuPdhQueryState
    {
        HQUERY queryHandle = nullptr;     // queryHandle: PDH query handle, reclaimed by the system when the process exits.
        HCOUNTER counterHandle = nullptr; // counterHandle: GPU Engine wildcard counter handle.
        bool permanentlyUnavailable = false; // permanentlyUnavailable: No available GPU Engine counters exist on the current system.
        bool hasBaselineSample = false;   // hasBaselineSample: The percentage counter requires at least two sampling rounds to produce a valid difference.
    };

    // GpuMemoryPdhQueryState：
    // - Maintain counters for dedicated/shared usage of \GPU Process Memory(*);
    // - Independent of GPU Engine queries to avoid dragging down the utilization counter baseline logic when the user only displays the VRAM column.
    struct GpuMemoryPdhQueryState
    {
        HQUERY queryHandle = nullptr;              // queryHandle: PDH query handle.
        HCOUNTER dedicatedCounterHandle = nullptr; // dedicatedCounterHandle: Dedicated Usage wildcard counter.
        HCOUNTER sharedCounterHandle = nullptr;    // sharedCounterHandle: Shared Usage wildcard counter.
        bool permanentlyUnavailable = false;       // permanentlyUnavailable: The current system does not have this counter set.
    };

    // gpuPdhQueryState:
    // - Returns the function's internal static state to avoid exposing global symbols;
    // - This state is accessed only under the mutual exclusion lock of QueryGpuUsagePercentByPid.
    GpuPdhQueryState& gpuPdhQueryState()
    {
        static GpuPdhQueryState state;
        return state;
    }

    // gpuPdhQueryMutex:
    // - Protects the PDH query handle and internal sampling state.
    // - Prevent PDH queries from being corrupted when multiple UI/background threads refresh the process list simultaneously.
    std::mutex& gpuPdhQueryMutex()
    {
        static std::mutex mutex;
        return mutex;
    }

    // gpuMemoryPdhQueryState:
    // - Returns the static state within the function for GPU memory counter queries;
    // - Access only under protection by gpuMemoryPdhQueryMutex.
    GpuMemoryPdhQueryState& gpuMemoryPdhQueryState()
    {
        static GpuMemoryPdhQueryState state;
        return state;
    }

    // gpuMemoryPdhQueryMutex:
    // - Protects the GPU memory PDH query handle.
    // - Uses a separate lock for GPU Engine queries to avoid mutual blocking.
    std::mutex& gpuMemoryPdhQueryMutex()
    {
        static std::mutex mutex;
        return mutex;
    }

    // addGpuEnglishCounter:
    // - Prioritize dynamically calling PdhAddEnglishCounterW to ensure English counter paths work on Chinese systems;
    // - If the export is missing in extremely old runtime environments, fall back to PdhAddCounterW.
    PDH_STATUS addGpuEnglishCounter(
        const HQUERY queryHandle,
        HCOUNTER* const counterHandleOut)
    {
        if (counterHandleOut == nullptr)
        {
            return ERROR_INVALID_PARAMETER;
        }

        HMODULE pdhModule = ::GetModuleHandleW(L"pdh.dll");
        if (pdhModule == nullptr)
        {
            pdhModule = ::LoadLibraryW(L"pdh.dll");
        }

        const auto kAddEnglishCounter = reinterpret_cast<PdhAddEnglishCounterWFn>(
            pdhModule != nullptr ? ::GetProcAddress(pdhModule, "PdhAddEnglishCounterW") : nullptr);
        if (kAddEnglishCounter != nullptr)
        {
            return kAddEnglishCounter(
                queryHandle,
                L"\\GPU Engine(*)\\Utilization Percentage",
                0,
                counterHandleOut);
        }

        return ::PdhAddCounterW(
            queryHandle,
            L"\\GPU Engine(*)\\Utilization Percentage",
            0,
            counterHandleOut);
    }

    // addPdhEnglishCounterByPath:
    // - Input: Open PDH query handle and English counter path;
    // - Handling: Prefer PdhAddEnglishCounterW; fall back to PdhAddCounterW on extremely old environments.
    // - Return: PDH_STATUS; caller uses this to decide whether to discard the counter set.
    PDH_STATUS addPdhEnglishCounterByPath(
        const HQUERY queryHandle,
        const wchar_t* const counterPath,
        HCOUNTER* const counterHandleOut)
    {
        if (counterHandleOut == nullptr || counterPath == nullptr)
        {
            return ERROR_INVALID_PARAMETER;
        }

        HMODULE pdhModule = ::GetModuleHandleW(L"pdh.dll");
        if (pdhModule == nullptr)
        {
            pdhModule = ::LoadLibraryW(L"pdh.dll");
        }

        const auto kAddEnglishCounter = reinterpret_cast<PdhAddEnglishCounterWFn>(
            pdhModule != nullptr ? ::GetProcAddress(pdhModule, "PdhAddEnglishCounterW") : nullptr);
        if (kAddEnglishCounter != nullptr)
        {
            return kAddEnglishCounter(queryHandle, counterPath, 0, counterHandleOut);
        }
        return ::PdhAddCounterW(queryHandle, counterPath, 0, counterHandleOut);
    }

    // resetGpuMemoryPdhQueryState:
    // - Disable GPU memory PDH query;
    // - When markUnavailable is true, re-initialization is skipped to avoid retrying on machines lacking this counter set in every iteration.
    void resetGpuMemoryPdhQueryState(
        GpuMemoryPdhQueryState& state,
        const bool markUnavailable)
    {
        if (state.queryHandle != nullptr)
        {
            ::PdhCloseQuery(state.queryHandle);
        }
        state.queryHandle = nullptr;
        state.dedicatedCounterHandle = nullptr;
        state.sharedCounterHandle = nullptr;
        if (markUnavailable)
        {
            state.permanentlyUnavailable = true;
        }
    }

    // ensureGpuMemoryPdhQueryReadyLocked:
    // - initialize wildcard counters for dedicated/shared usage of \GPU Process Memory(*);
    // - Caller must already hold gpuMemoryPdhQueryMutex.
    // - Returns false if GPU memory counters cannot be read under the current system/permissions.
    bool ensureGpuMemoryPdhQueryReadyLocked(GpuMemoryPdhQueryState& state)
    {
        if (state.permanentlyUnavailable)
        {
            return false;
        }
        if (state.queryHandle != nullptr &&
            state.dedicatedCounterHandle != nullptr &&
            state.sharedCounterHandle != nullptr)
        {
            return true;
        }

        HQUERY queryHandle = nullptr;
        PDH_STATUS status = ::PdhOpenQueryW(nullptr, 0, &queryHandle);
        if (status != ERROR_SUCCESS || queryHandle == nullptr)
        {
            resetGpuMemoryPdhQueryState(state, true);
            return false;
        }

        HCOUNTER dedicatedCounter = nullptr;
        status = addPdhEnglishCounterByPath(
            queryHandle,
            L"\\GPU Process Memory(*)\\Dedicated Usage",
            &dedicatedCounter);
        if (status != ERROR_SUCCESS || dedicatedCounter == nullptr)
        {
            ::PdhCloseQuery(queryHandle);
            resetGpuMemoryPdhQueryState(state, true);
            return false;
        }

        HCOUNTER sharedCounter = nullptr;
        status = addPdhEnglishCounterByPath(
            queryHandle,
            L"\\GPU Process Memory(*)\\Shared Usage",
            &sharedCounter);
        if (status != ERROR_SUCCESS || sharedCounter == nullptr)
        {
            ::PdhCloseQuery(queryHandle);
            resetGpuMemoryPdhQueryState(state, true);
            return false;
        }

        state.queryHandle = queryHandle;
        state.dedicatedCounterHandle = dedicatedCounter;
        state.sharedCounterHandle = sharedCounter;
        state.permanentlyUnavailable = false;
        return true;
    }

    // resetGpuPdhQueryState:
    // - Close the current PDH query.
    // - When markUnavailable is true, re-initialization is skipped to avoid repeated overhead on machines without GPUs.
    void resetGpuPdhQueryState(
        GpuPdhQueryState& state,
        const bool markUnavailable)
    {
        if (state.queryHandle != nullptr)
        {
            ::PdhCloseQuery(state.queryHandle);
        }
        state.queryHandle = nullptr;
        state.counterHandle = nullptr;
        state.hasBaselineSample = false;
        if (markUnavailable)
        {
            state.permanentlyUnavailable = true;
        }
    }

    // ensureGpuPdhQueryReadyLocked:
    // - initialize Windows GPU Engine PDH wildcard counters.
    // - Caller must already hold gpuPdhQueryMutex;
    // - Returns false if the GPU Engine cannot be read under the current system or permission context.
    bool ensureGpuPdhQueryReadyLocked(GpuPdhQueryState& state)
    {
        if (state.permanentlyUnavailable)
        {
            return false;
        }
        if (state.queryHandle != nullptr && state.counterHandle != nullptr)
        {
            return true;
        }

        HQUERY queryHandle = nullptr;
        PDH_STATUS status = ::PdhOpenQueryW(nullptr, 0, &queryHandle);
        if (status != ERROR_SUCCESS || queryHandle == nullptr)
        {
            resetGpuPdhQueryState(state, true);
            return false;
        }

        HCOUNTER counterHandle = nullptr;
        // Use the English Counter path to avoid AddCounter failures caused by localized counter names on Chinese systems.
        // addGpuEnglishCounter internally falls back to PdhAddCounterW in extremely old environments.
        status = addGpuEnglishCounter(queryHandle, &counterHandle);
        if (status != ERROR_SUCCESS || counterHandle == nullptr)
        {
            ::PdhCloseQuery(queryHandle);
            resetGpuPdhQueryState(state, true);
            return false;
        }

        state.queryHandle = queryHandle;
        state.counterHandle = counterHandle;
        state.hasBaselineSample = false;
        state.permanentlyUnavailable = false;
        return true;
    }

    // queryGpuUsageByPid:
    // - Read \GPU Engine(*)\Utilization Percentage;
    // - Aggregate multiple engines for the same process by pid_XXXX in the instance name;
    // - When the collectEngineText parameter is true, additionally record the display name of the engine with the highest usage (the 'GPU Engine' column in Task Manager).
    // - Returns PID -> GPU usage summary; returns an empty map on failure.
    std::unordered_map<std::uint32_t, GpuProcessUsageSample> queryGpuUsageByPid(const bool collectEngineText)
    {
        std::unordered_map<std::uint32_t, GpuProcessUsageSample> gpuUsageByPid;

        std::lock_guard<std::mutex> queryLock(gpuPdhQueryMutex());
        GpuPdhQueryState& state = gpuPdhQueryState();
        if (!ensureGpuPdhQueryReadyLocked(state))
        {
            return gpuUsageByPid;
        }

        const PDH_STATUS kCollectStatus = ::PdhCollectQueryData(state.queryHandle);
        if (kCollectStatus != ERROR_SUCCESS)
        {
            // Allow query reconstruction in the next round when temporary sampling fails, preventing long-term hangs after device reset.
            resetGpuPdhQueryState(state, false);
            return gpuUsageByPid;
        }
        if (!state.hasBaselineSample)
        {
            // GPU Engine Utilization Percentage requires baseline samples, just like the System Informer PDH scheme.
            // The first Collect call only establishes internal historical values; the formatted array is read on the next refresh to avoid false positives in the initial round.
            state.hasBaselineSample = true;
            return gpuUsageByPid;
        }

        DWORD bufferSize = 0;
        DWORD itemCount = 0;
        PDH_STATUS formatStatus = ::PdhGetFormattedCounterArrayW(
            state.counterHandle,
            PDH_FMT_DOUBLE,
            &bufferSize,
            &itemCount,
            nullptr);
        if (formatStatus == PDH_INVALID_DATA)
        {
            // Many PDH percentage counters require two Collect calls; the first round having no historical samples is normal warm-up.
            return gpuUsageByPid;
        }
        if (formatStatus != PDH_MORE_DATA || bufferSize == 0 || itemCount == 0)
        {
            return gpuUsageByPid;
        }

        // The PDH output buffer contains both a structure array and instance name strings.
        // Using uint64_t as the underlying storage satisfies alignment requirements for pointers and DOUBLE fields.
        std::vector<std::uint64_t> itemStorage(
            (static_cast<std::size_t>(bufferSize) + sizeof(std::uint64_t) - 1U) /
            sizeof(std::uint64_t));
        auto* const kItemList = reinterpret_cast<PDH_FMT_COUNTERVALUE_ITEM_W*>(itemStorage.data());
        formatStatus = ::PdhGetFormattedCounterArrayW(
            state.counterHandle,
            PDH_FMT_DOUBLE,
            &bufferSize,
            &itemCount,
            kItemList);
        if (formatStatus != ERROR_SUCCESS)
        {
            return gpuUsageByPid;
        }

        gpuUsageByPid.reserve(static_cast<std::size_t>(itemCount));
        for (DWORD itemIndex = 0; itemIndex < itemCount; ++itemIndex)
        {
            const PDH_FMT_COUNTERVALUE_ITEM_W& item = kItemList[itemIndex];
            const std::uint32_t kProcessId = extractPidFromGpuEngineInstanceName(item.szName);
            if (kProcessId == 0)
            {
                continue;
            }
            if (item.FmtValue.CStatus != ERROR_SUCCESS)
            {
                continue;
            }

            const double kEnginePercent = item.FmtValue.doubleValue;
            if (!std::isfinite(kEnginePercent) || kEnginePercent <= 0.0)
            {
                continue;
            }

            // The same PID may use multiple engines (3D/Copy/VideoDecode/Compute) simultaneously; this sums them up.
            GpuProcessUsageSample& usageSample = gpuUsageByPid[kProcessId];
            usageSample.utilizationPercent += kEnginePercent;

            // The 'GPU Engine' column displays the engine with the highest usage, consistent with Task Manager.
            if (collectEngineText && kEnginePercent > usageSample.topEnginePercent)
            {
                std::string engineDisplayText = extractGpuEngineDisplayText(item.szName);
                if (!engineDisplayText.empty())
                {
                    usageSample.topEnginePercent = kEnginePercent;
                    usageSample.topEngineText = std::move(engineDisplayText);
                }
            }
        }

        for (auto& gpuPair : gpuUsageByPid)
        {
            // UI columns display 0–100%; abnormal cumulative values are clamped to prevent sorting and highlighting issues in multi-adapter scenarios.
            gpuPair.second.utilizationPercent =
                std::clamp(gpuPair.second.utilizationPercent, 0.0, 100.0);
        }
        return gpuUsageByPid;
    }

    // queryGpuProcessMemoryByPid:
    // - Read \GPU Process Memory(*)\Dedicated Usage and Shared Usage;
    // - Both counters are instantaneous raw values; no baseline sample needed;
    // - Returns PID -> VRAM usage; returns an empty map when counters are unavailable.
    std::unordered_map<std::uint32_t, GpuProcessMemorySample> queryGpuProcessMemoryByPid()
    {
        std::unordered_map<std::uint32_t, GpuProcessMemorySample> gpuMemoryByPid;

        std::lock_guard<std::mutex> queryLock(gpuMemoryPdhQueryMutex());
        GpuMemoryPdhQueryState& state = gpuMemoryPdhQueryState();
        if (!ensureGpuMemoryPdhQueryReadyLocked(state))
        {
            return gpuMemoryByPid;
        }

        const PDH_STATUS kCollectStatus = ::PdhCollectQueryData(state.queryHandle);
        if (kCollectStatus != ERROR_SUCCESS)
        {
            resetGpuMemoryPdhQueryState(state, false);
            return gpuMemoryByPid;
        }

        // accumulateCounter: Aggregates all instances of a wildcard counter by PID into the target field.
        const auto kAccumulateCounter =
            [&gpuMemoryByPid](const HCOUNTER counterHandle, const bool writeDedicated) -> void
            {
                if (counterHandle == nullptr)
                {
                    return;
                }

                DWORD bufferSize = 0;
                DWORD itemCount = 0;
                PDH_STATUS formatStatus = ::PdhGetFormattedCounterArrayW(
                    counterHandle,
                    PDH_FMT_LARGE,
                    &bufferSize,
                    &itemCount,
                    nullptr);
                if (formatStatus != PDH_MORE_DATA || bufferSize == 0 || itemCount == 0)
                {
                    return;
                }

                std::vector<std::uint64_t> itemStorage(
                    (static_cast<std::size_t>(bufferSize) + sizeof(std::uint64_t) - 1U) /
                    sizeof(std::uint64_t));
                auto* const kItemList = reinterpret_cast<PDH_FMT_COUNTERVALUE_ITEM_W*>(itemStorage.data());
                formatStatus = ::PdhGetFormattedCounterArrayW(
                    counterHandle,
                    PDH_FMT_LARGE,
                    &bufferSize,
                    &itemCount,
                    kItemList);
                if (formatStatus != ERROR_SUCCESS)
                {
                    return;
                }

                for (DWORD itemIndex = 0; itemIndex < itemCount; ++itemIndex)
                {
                    const PDH_FMT_COUNTERVALUE_ITEM_W& item = kItemList[itemIndex];
                    const std::uint32_t kProcessId = extractPidFromGpuEngineInstanceName(item.szName);
                    if (kProcessId == 0 || item.FmtValue.CStatus != ERROR_SUCCESS)
                    {
                        continue;
                    }
                    if (item.FmtValue.largeValue <= 0)
                    {
                        continue;
                    }

                    // The same process may have GPU memory instances on multiple adapters; sum by PID.
                    const std::uint64_t kUsageBytes = static_cast<std::uint64_t>(item.FmtValue.largeValue);
                    GpuProcessMemorySample& memorySample = gpuMemoryByPid[kProcessId];
                    if (writeDedicated)
                    {
                        memorySample.dedicatedBytes += kUsageBytes;
                    }
                    else
                    {
                        memorySample.sharedBytes += kUsageBytes;
                    }
                }
            };

        kAccumulateCounter(state.dedicatedCounterHandle, true);
        kAccumulateCounter(state.sharedCounterHandle, false);
        return gpuMemoryByPid;
    }

    // applyGpuUsageCountersToProcessList:
    // - Write back the GPU utilization aggregated by PID to the process snapshot.
    // - Parameter detailDemandFlags determines whether to additionally collect engine names and VRAM usage.
    // - When PDH is unavailable, keep the default 0 without affecting the main process enumeration flow.
    void applyGpuUsageCountersToProcessList(
        std::vector<ks::process::ProcessRecord>& processList,
        const std::uint32_t detailDemandFlags)
    {
        if (processList.empty())
        {
            return;
        }

        const bool kCollectEngineText =
            (detailDemandFlags & ks::process::process_detail_demand::kGpuEngine) != 0U;
        const std::unordered_map<std::uint32_t, GpuProcessUsageSample> kGpuUsageByPid =
            queryGpuUsageByPid(kCollectEngineText);
        if (!kGpuUsageByPid.empty())
        {
            for (ks::process::ProcessRecord& processRecord : processList)
            {
                const auto kGpuIt = kGpuUsageByPid.find(processRecord.pid);
                if (kGpuIt == kGpuUsageByPid.end())
                {
                    processRecord.gpuPercent = 0.0;
                    continue;
                }
                processRecord.gpuPercent = kGpuIt->second.utilizationPercent;
                if (kCollectEngineText)
                {
                    processRecord.gpuEngineText = kGpuIt->second.topEngineText;
                }
            }
        }

        // GPU memory column is hidden by default; an extra PDH sample is taken for the entire table only when user-related columns are displayed.
        if ((detailDemandFlags & ks::process::process_detail_demand::kGpuMemory) == 0U)
        {
            return;
        }

        const std::unordered_map<std::uint32_t, GpuProcessMemorySample> kGpuMemoryByPid =
            queryGpuProcessMemoryByPid();
        if (kGpuMemoryByPid.empty())
        {
            return;
        }

        for (ks::process::ProcessRecord& processRecord : processList)
        {
            const auto kMemoryIt = kGpuMemoryByPid.find(processRecord.pid);
            processRecord.gpuDedicatedMemoryBytes =
                (kMemoryIt == kGpuMemoryByPid.end()) ? 0ULL : kMemoryIt->second.dedicatedBytes;
            processRecord.gpuSharedMemoryBytes =
                (kMemoryIt == kGpuMemoryByPid.end()) ? 0ULL : kMemoryIt->second.sharedBytes;
            processRecord.gpuMemoryKnown = true;
        }
    }

    // Read the process executable path (UTF-8); return an empty string on failure.
    std::string queryProcessPathByHandle(const HANDLE processHandle)
    {
        if (processHandle == nullptr || processHandle == INVALID_HANDLE_VALUE)
        {
            return std::string();
        }

        // Path query prefers QueryFullProcessImageNameW (supports QUERY_LIMITED_INFORMATION).
        std::wstring pathBuffer(32768, L'\0');
        DWORD pathLength = static_cast<DWORD>(pathBuffer.size());
        if (::QueryFullProcessImageNameW(processHandle, 0, pathBuffer.data(), &pathLength) != FALSE)
        {
            pathBuffer.resize(pathLength);
            return ks::str::utf16ToUtf8(pathBuffer);
        }

        // Fallback path: GetModuleFileNameExW (can read some processes that fail with the former).
        std::wstring modulePathBuffer(32768, L'\0');
        const DWORD kModulePathLength = ::GetModuleFileNameExW(
            processHandle,
            nullptr,
            modulePathBuffer.data(),
            static_cast<DWORD>(modulePathBuffer.size()));
        if (kModulePathLength > 0)
        {
            modulePathBuffer.resize(kModulePathLength);
            return ks::str::utf16ToUtf8(modulePathBuffer);
        }

        return std::string();
    }

    // queryProcessStartTimeByPid:
    // - Read process creation time (FILETIME) by PID;
    // - Used to populate the RM_UNIQUE_PROCESS structure for Restart Manager.
    bool queryProcessStartTimeByPid(const std::uint32_t pid, FILETIME* const creationTimeOut)
    {
        if (creationTimeOut == nullptr || pid == 0)
        {
            return false;
        }

        const HANDLE kProcessHandle = ::OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION,
            FALSE,
            static_cast<DWORD>(pid));
        if (kProcessHandle == nullptr)
        {
            return false;
        }

        FILETIME creationTime{};
        FILETIME exitTime{};
        FILETIME kernelTime{};
        FILETIME userTime{};
        const BOOL kQueryResult = ::GetProcessTimes(
            kProcessHandle,
            &creationTime,
            &exitTime,
            &kernelTime,
            &userTime);
        ::CloseHandle(kProcessHandle);
        if (kQueryResult == FALSE)
        {
            return false;
        }

        *creationTimeOut = creationTime;
        return true;
    }

    // queryModuleBaseAddressBySnapshot:
    // - Locates the target module base address via module snapshot.
    // - Used to locate the remote ntdll.dll mapping address for NtUnmapViewOfSection.
    bool queryModuleBaseAddressBySnapshot(
        const std::uint32_t pid,
        const wchar_t* const moduleNameText,
        void** const baseAddressOut)
    {
        if (baseAddressOut == nullptr || moduleNameText == nullptr || pid == 0)
        {
            return false;
        }
        *baseAddressOut = nullptr;

        const HANDLE kSnapshotHandle = ::CreateToolhelp32Snapshot(
            TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
            static_cast<DWORD>(pid));
        if (kSnapshotHandle == INVALID_HANDLE_VALUE)
        {
            return false;
        }

        MODULEENTRY32W moduleEntry{};
        moduleEntry.dwSize = sizeof(moduleEntry);
        if (::Module32FirstW(kSnapshotHandle, &moduleEntry) == FALSE)
        {
            ::CloseHandle(kSnapshotHandle);
            return false;
        }

        do
        {
            if (_wcsicmp(moduleEntry.szModule, moduleNameText) == 0)
            {
                *baseAddressOut = moduleEntry.modBaseAddr;
                ::CloseHandle(kSnapshotHandle);
                return true;
            }
        } while (::Module32NextW(kSnapshotHandle, &moduleEntry) != FALSE);

        ::CloseHandle(kSnapshotHandle);
        return false;
    }

    // Query the username in DOMAIN\\User format via the token.
    std::string queryProcessUserNameByHandle(const HANDLE processHandle)
    {
        HANDLE processToken = nullptr;
        if (::OpenProcessToken(processHandle, TOKEN_QUERY, &processToken) == FALSE)
        {
            return std::string();
        }

        DWORD requiredLength = 0;
        ::GetTokenInformation(processToken, TokenUser, nullptr, 0, &requiredLength);
        if (requiredLength == 0)
        {
            ::CloseHandle(processToken);
            return std::string();
        }

        std::vector<BYTE> tokenBuffer(requiredLength);
        if (::GetTokenInformation(processToken, TokenUser, tokenBuffer.data(), requiredLength, &requiredLength) == FALSE)
        {
            ::CloseHandle(processToken);
            return std::string();
        }

        const auto* tokenUser = reinterpret_cast<const TOKEN_USER*>(tokenBuffer.data());
        wchar_t accountName[256] = {};
        wchar_t domainName[256] = {};
        DWORD accountNameLength = static_cast<DWORD>(std::size(accountName));
        DWORD domainNameLength = static_cast<DWORD>(std::size(domainName));
        SID_NAME_USE sidUse = SidTypeUnknown;

        const BOOL kLookupResult = ::LookupAccountSidW(
            nullptr,
            tokenUser->User.Sid,
            accountName,
            &accountNameLength,
            domainName,
            &domainNameLength,
            &sidUse);
        ::CloseHandle(processToken);

        if (kLookupResult == FALSE)
        {
            return std::string();
        }

        std::wstring fullUserName(domainName);
        if (!fullUserName.empty())
        {
            fullUserName += L"\\";
        }
        fullUserName += accountName;
        return ks::str::utf16ToUtf8(fullUserName);
    }

    // Query whether the process token is elevated (Administrator).
    bool queryProcessIsElevatedByHandle(const HANDLE processHandle)
    {
        HANDLE processToken = nullptr;
        if (::OpenProcessToken(processHandle, TOKEN_QUERY, &processToken) == FALSE)
        {
            return false;
        }

        TOKEN_ELEVATION tokenElevation{};
        DWORD returnLength = 0;
        const BOOL kQueryResult = ::GetTokenInformation(
            processToken,
            TokenElevation,
            &tokenElevation,
            sizeof(tokenElevation),
            &returnLength);
        ::CloseHandle(processToken);

        if (kQueryResult == FALSE)
        {
            return false;
        }
        return tokenElevation.TokenIsElevated != 0;
    }

    // FileSignatureInfo: Aggregation structure for single-file signature information.
    // This structure carries both:
    // 1) Publisher;
    // 2) Whether it is trusted and accepted by a Windows trust chain.
    // 3) Display text directly in the UI.
    struct FileSignatureInfo
    {
        bool hasSignature = false;         // Whether a signature was detected.
        bool trustedByWindows = false;     // Whether it is determined to be trusted by WinVerifyTrust.
        std::string publisher;             // Certificate publisher or manufacturer name.
        std::string displayText;           // UI display text (includes vendor and trust status).
    };

    // queryCompanyNameByVersion:
    // - Read CompanyName from file version information;
    // - Fallback manufacturer text when the certificate publisher is empty.
    std::string queryCompanyNameByVersion(const std::wstring& utf16Path)
    {
        if (utf16Path.empty())
        {
            return std::string();
        }

        DWORD versionHandle = 0;
        const DWORD kVersionInfoSize = ::GetFileVersionInfoSizeW(utf16Path.c_str(), &versionHandle);
        if (kVersionInfoSize == 0)
        {
            return std::string();
        }

        std::vector<BYTE> versionInfoBuffer(kVersionInfoSize, 0);
        if (::GetFileVersionInfoW(
            utf16Path.c_str(),
            0,
            kVersionInfoSize,
            versionInfoBuffer.data()) == FALSE)
        {
            return std::string();
        }

        // Prioritize reading the language code page mapping to ensure correct localized strings are retrieved.
        struct LangAndCodePage
        {
            WORD language = 0;
            WORD codePage = 0;
        };
        LangAndCodePage* translation = nullptr;
        UINT translationSize = 0;
        if (::VerQueryValueW(
            versionInfoBuffer.data(),
            L"\\VarFileInfo\\Translation",
            reinterpret_cast<LPVOID*>(&translation),
            &translationSize) != FALSE &&
            translation != nullptr &&
            translationSize >= sizeof(LangAndCodePage))
        {
            wchar_t queryPath[96] = {};
            std::swprintf(
                queryPath,
                std::size(queryPath),
                L"\\StringFileInfo\\%04x%04x\\CompanyName",
                translation[0].language,
                translation[0].codePage);

            LPVOID companyValue = nullptr;
            UINT companyLength = 0;
            if (::VerQueryValueW(
                versionInfoBuffer.data(),
                queryPath,
                &companyValue,
                &companyLength) != FALSE &&
                companyValue != nullptr &&
                companyLength > 0)
            {
                return ks::str::utf16ToUtf8(static_cast<const wchar_t*>(companyValue));
            }
        }

        // If language mapping is missing, attempt a fallback to a common English code page.
        LPVOID fallbackValue = nullptr;
        UINT fallbackLength = 0;
        if (::VerQueryValueW(
            versionInfoBuffer.data(),
            L"\\StringFileInfo\\040904B0\\CompanyName",
            &fallbackValue,
            &fallbackLength) != FALSE &&
            fallbackValue != nullptr &&
            fallbackLength > 0)
        {
            return ks::str::utf16ToUtf8(static_cast<const wchar_t*>(fallbackValue));
        }

        return std::string();
    }

    // queryVersionStringValue:
    // - Input: Full image path and entry name in StringFileInfo (e.g., "FileDescription");
    // - Processing: Prefer reading using the file's native language/code page; fall back to English code page if missing.
    // - Returns: UTF-8 text; returns an empty string if the file lacks version resources or the entry does not exist.
    std::string queryVersionStringValue(
        const std::wstring& utf16Path,
        const wchar_t* const valueName)
    {
        if (utf16Path.empty() || valueName == nullptr)
        {
            return std::string();
        }

        DWORD versionHandle = 0;
        const DWORD kVersionInfoSize = ::GetFileVersionInfoSizeW(utf16Path.c_str(), &versionHandle);
        if (kVersionInfoSize == 0)
        {
            return std::string();
        }

        std::vector<BYTE> versionInfoBuffer(kVersionInfoSize, 0);
        if (::GetFileVersionInfoW(
            utf16Path.c_str(),
            0,
            kVersionInfoSize,
            versionInfoBuffer.data()) == FALSE)
        {
            return std::string();
        }

        struct LangAndCodePage
        {
            WORD language = 0;
            WORD codePage = 0;
        };
        LangAndCodePage* translation = nullptr;
        UINT translationSize = 0;
        if (::VerQueryValueW(
            versionInfoBuffer.data(),
            L"\\VarFileInfo\\Translation",
            reinterpret_cast<LPVOID*>(&translation),
            &translationSize) != FALSE &&
            translation != nullptr &&
            translationSize >= sizeof(LangAndCodePage))
        {
            wchar_t queryPath[128] = {};
            std::swprintf(
                queryPath,
                std::size(queryPath),
                L"\\StringFileInfo\\%04x%04x\\%s",
                translation[0].language,
                translation[0].codePage,
                valueName);

            LPVOID stringValue = nullptr;
            UINT stringLength = 0;
            if (::VerQueryValueW(
                versionInfoBuffer.data(),
                queryPath,
                &stringValue,
                &stringLength) != FALSE &&
                stringValue != nullptr &&
                stringLength > 0)
            {
                return ks::str::utf16ToUtf8(static_cast<const wchar_t*>(stringValue));
            }
        }

        wchar_t fallbackPath[128] = {};
        std::swprintf(
            fallbackPath,
            std::size(fallbackPath),
            L"\\StringFileInfo\\040904B0\\%s",
            valueName);

        LPVOID fallbackValue = nullptr;
        UINT fallbackLength = 0;
        if (::VerQueryValueW(
            versionInfoBuffer.data(),
            fallbackPath,
            &fallbackValue,
            &fallbackLength) != FALSE &&
            fallbackValue != nullptr &&
            fallbackLength > 0)
        {
            return ks::str::utf16ToUtf8(static_cast<const wchar_t*>(fallbackValue));
        }

        return std::string();
    }

    // ImageOsContextGuidMapping：
    // - Mapping from manifest <supportedOS Id="{GUID}"/> entries to system names.
    // - Ordered from newest to oldest; take the first match, consistent with Task Manager's 'OS Context' display showing the highest supported OS.
    struct ImageOsContextGuidMapping
    {
        const wchar_t* guidText; // GUID in the supportedOS Id attribute (lowercase, with braces).
        const char* displayText; // System name for display.
    };

    const ImageOsContextGuidMapping kImageOsContextGuidMappings[] =
    {
        { L"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}", "Windows 10" },
        { L"{1f676c76-80e1-4239-95bb-83d0f6d0da78}", "Windows 8.1" },
        { L"{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}", "Windows 8" },
        { L"{35138b9a-5d96-4fbd-8e2d-a2440225f93a}", "Windows 7" },
        { L"{e2011457-1546-43c5-a5fe-008deee3d3f0}", "Windows Vista" }
    };

    // queryImageOsContextText:
    // - Input: Full image path;
    // - Processing: Map PE in 'resources-only' mode, read RT_MANIFEST, and search for supportedOS GUID within it.
    // - Return: matched system name; return empty string if the image lacks a compatibility manifest (same as Task Manager).
    // Security: Using LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE ensures that code in the target image is not executed.
    std::string queryImageOsContextText(const std::wstring& utf16Path)
    {
        if (utf16Path.empty())
        {
            return std::string();
        }

        const HMODULE kImageModule = ::LoadLibraryExW(
            utf16Path.c_str(),
            nullptr,
            LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE);
        if (kImageModule == nullptr)
        {
            return std::string();
        }

        std::string manifestText;
        // Common manifest resource IDs: 1=CREATEPROCESS_MANIFEST_RESOURCE_ID, 2/3 are ISOLATIONAWARE variants.
        for (WORD manifestId = 1; manifestId <= 3 && manifestText.empty(); ++manifestId)
        {
            const HRSRC kResourceHandle = ::FindResourceW(
                kImageModule,
                MAKEINTRESOURCEW(manifestId),
                MAKEINTRESOURCEW(24 /* RT_MANIFEST */));
            if (kResourceHandle == nullptr)
            {
                continue;
            }

            const DWORD kResourceSize = ::SizeofResource(kImageModule, kResourceHandle);
            if (kResourceSize == 0)
            {
                continue;
            }

            const HGLOBAL kResourceData = ::LoadResource(kImageModule, kResourceHandle);
            if (kResourceData == nullptr)
            {
                continue;
            }

            const void* const kResourceBytes = ::LockResource(kResourceData);
            if (kResourceBytes == nullptr)
            {
                continue;
            }

            // The manifest is UTF-8 XML text; the limit protects against oversized allocations caused by anomalous resources.
            constexpr DWORD kManifestMaxBytes = 1024U * 1024U;
            manifestText.assign(
                static_cast<const char*>(kResourceBytes),
                static_cast<std::size_t>(std::min(kResourceSize, kManifestMaxBytes)));
        }

        ::FreeLibrary(kImageModule);
        if (manifestText.empty())
        {
            return std::string();
        }

        // GUID case sensitivity is inconsistent across manifests generated by different toolchains; convert to lowercase before comparison.
        for (char& manifestChar : manifestText)
        {
            if (manifestChar >= 'A' && manifestChar <= 'Z')
            {
                manifestChar = static_cast<char>(manifestChar - 'A' + 'a');
            }
        }

        for (const ImageOsContextGuidMapping& mapping : kImageOsContextGuidMappings)
        {
            const std::string kGuidNarrow = ks::str::utf16ToUtf8(mapping.guidText);
            if (manifestText.find(kGuidNarrow) != std::string::npos)
            {
                return std::string(mapping.displayText);
            }
        }

        return std::string();
    }

    // ImageDescriptionCacheEntry: cached 'description / OS context' resolution results by image path.
    struct ImageDescriptionCacheEntry
    {
        std::string fileDescription;    // Version resource FileDescription.
        std::string osContextText;      // System name mapped from the supportedOS manifest.
        bool descriptionResolved = false; // true indicates that FileDescription resolution has been attempted (including resolving to an empty string).
        bool osContextResolved = false;   // true indicates that the manifest has been attempted to be resolved.
    };

    // imageDescriptionCache:
    // - Note: The OS context depends solely on the image file on disk; processes with the same name can fully share results.
    // - Caches per-process per-round PE parsing to once per image, enabling these two columns to remain permanently displayed.
    std::unordered_map<std::string, ImageDescriptionCacheEntry>& imageDescriptionCache()
    {
        static std::unordered_map<std::string, ImageDescriptionCacheEntry> cache;
        return cache;
    }

    // imageDescriptionCacheMutex purpose: Protects imageDescriptionCache for concurrent access by background multi-threaded static completion.
    std::mutex& imageDescriptionCacheMutex()
    {
        static std::mutex mutex;
        return mutex;
    }

    // ImageDescriptionCacheMaximumEntryCount：
    // - Maximum cache entry limit; upon reaching the limit, the entire cache is cleared and rebuilt to prevent unbounded growth after long-running execution.
    constexpr std::size_t kImageDescriptionCacheMaximumEntryCount = 4096;

    // resolveImageDescriptionCached:
    // - Input: Image path and required fields for this request (description / OS context).
    // - Processing: Return immediately if the cache is hit; otherwise, parse once and write back to the cache.
    // - Return: No return value; results are returned via output parameters.
    void resolveImageDescriptionCached(
        const std::string& imagePath,
        const bool wantFileDescription,
        const bool wantOsContext,
        std::string* const fileDescriptionOut,
        std::string* const osContextTextOut)
    {
        if (imagePath.empty() || (!wantFileDescription && !wantOsContext))
        {
            return;
        }

        {
            std::lock_guard<std::mutex> cacheLock(imageDescriptionCacheMutex());
            const auto kCacheIt = imageDescriptionCache().find(imagePath);
            if (kCacheIt != imageDescriptionCache().end())
            {
                const ImageDescriptionCacheEntry& cachedEntry = kCacheIt->second;
                const bool kDescriptionSatisfied = !wantFileDescription || cachedEntry.descriptionResolved;
                const bool kOsContextSatisfied = !wantOsContext || cachedEntry.osContextResolved;
                if (kDescriptionSatisfied && kOsContextSatisfied)
                {
                    if (wantFileDescription && fileDescriptionOut != nullptr)
                    {
                        *fileDescriptionOut = cachedEntry.fileDescription;
                    }
                    if (wantOsContext && osContextTextOut != nullptr)
                    {
                        *osContextTextOut = cachedEntry.osContextText;
                    }
                    return;
                }
            }
        }

        // No lock held during parsing: PE mapping and version resource reading may involve disk I/O.
        const std::wstring kUtf16Path = ks::str::utf8ToUtf16(imagePath);
        std::string resolvedDescription;
        std::string resolvedOsContext;
        if (wantFileDescription)
        {
            resolvedDescription = queryVersionStringValue(kUtf16Path, L"FileDescription");
        }
        if (wantOsContext)
        {
            resolvedOsContext = queryImageOsContextText(kUtf16Path);
        }

        {
            std::lock_guard<std::mutex> cacheLock(imageDescriptionCacheMutex());
            if (imageDescriptionCache().size() >= kImageDescriptionCacheMaximumEntryCount)
            {
                imageDescriptionCache().clear();
            }

            ImageDescriptionCacheEntry& cacheEntry = imageDescriptionCache()[imagePath];
            if (wantFileDescription)
            {
                cacheEntry.fileDescription = resolvedDescription;
                cacheEntry.descriptionResolved = true;
            }
            if (wantOsContext)
            {
                cacheEntry.osContextText = resolvedOsContext;
                cacheEntry.osContextResolved = true;
            }
        }

        if (wantFileDescription && fileDescriptionOut != nullptr)
        {
            *fileDescriptionOut = std::move(resolvedDescription);
        }
        if (wantOsContext && osContextTextOut != nullptr)
        {
            *osContextTextOut = std::move(resolvedOsContext);
        }
    }

    // queryProcessUacVirtualizationStateByHandle:
    // - Input: A process handle with PROCESS_QUERY_LIMITED_INFORMATION access;
    // - Processing: Read the token's TokenVirtualizationAllowed / TokenVirtualizationEnabled;
    // - Return: One of three UAC virtualization states; returns Unknown if the token cannot be opened.
    ks::process::ProcessFeatureState queryProcessUacVirtualizationStateByHandle(const HANDLE processHandle)
    {
        if (processHandle == nullptr || processHandle == INVALID_HANDLE_VALUE)
        {
            return ks::process::ProcessFeatureState::kUnknown;
        }

        HANDLE tokenHandle = nullptr;
        if (::OpenProcessToken(processHandle, TOKEN_QUERY, &tokenHandle) == FALSE || tokenHandle == nullptr)
        {
            return ks::process::ProcessFeatureState::kUnknown;
        }

        DWORD virtualizationAllowed = 0;
        DWORD returnLength = 0;
        const BOOL kAllowedOk = ::GetTokenInformation(
            tokenHandle,
            TokenVirtualizationAllowed,
            &virtualizationAllowed,
            static_cast<DWORD>(sizeof(virtualizationAllowed)),
            &returnLength);
        if (kAllowedOk == FALSE)
        {
            ::CloseHandle(tokenHandle);
            return ks::process::ProcessFeatureState::kUnknown;
        }
        if (virtualizationAllowed == 0)
        {
            // 64-bit processes and most system components do not support virtualization; Task Manager displays 'Not Allowed'.
            ::CloseHandle(tokenHandle);
            return ks::process::ProcessFeatureState::kNotAllowed;
        }

        DWORD virtualizationEnabled = 0;
        const BOOL kEnabledOk = ::GetTokenInformation(
            tokenHandle,
            TokenVirtualizationEnabled,
            &virtualizationEnabled,
            static_cast<DWORD>(sizeof(virtualizationEnabled)),
            &returnLength);
        ::CloseHandle(tokenHandle);
        if (kEnabledOk == FALSE)
        {
            return ks::process::ProcessFeatureState::kUnknown;
        }
        return (virtualizationEnabled != 0)
            ? ks::process::ProcessFeatureState::kEnabled
            : ks::process::ProcessFeatureState::kDisabled;
    }

    // applyProcessMitigationStatesByHandle:
    // - Input: process handle;
    // - Processing: Read data to apply execution protection and control flow protection mitigation policies;
    // - Returns: true if at least one policy was read successfully.
    // Compatibility: GetProcessMitigationPolicy is available from Windows 8 onwards; safely skip on older systems after dynamic resolution.
    bool applyProcessMitigationStatesByHandle(
        ks::process::ProcessRecord& processRecord,
        const HANDLE processHandle)
    {
        if (processHandle == nullptr || processHandle == INVALID_HANDLE_VALUE)
        {
            return false;
        }

        using GetProcessMitigationPolicyFn =
            BOOL(WINAPI*)(HANDLE, PROCESS_MITIGATION_POLICY, PVOID, SIZE_T);
        HMODULE kernel32Module = ::GetModuleHandleW(L"kernel32.dll");
        const auto kGetProcessMitigationPolicy = reinterpret_cast<GetProcessMitigationPolicyFn>(
            kernel32Module != nullptr
            ? ::GetProcAddress(kernel32Module, "GetProcessMitigationPolicy")
            : nullptr);
        if (kGetProcessMitigationPolicy == nullptr)
        {
            return false;
        }

        bool anySucceeded = false;

        PROCESS_MITIGATION_DEP_POLICY depPolicy{};
        if (kGetProcessMitigationPolicy(
            processHandle,
            ProcessDEPPolicy,
            &depPolicy,
            sizeof(depPolicy)) != FALSE)
        {
            if (depPolicy.Enable == 0)
            {
                processRecord.dataExecutionPreventionState = ks::process::ProcessFeatureState::kDisabled;
            }
            else
            {
                processRecord.dataExecutionPreventionState = (depPolicy.Permanent != FALSE)
                    ? ks::process::ProcessFeatureState::kEnabledPermanent
                    : ks::process::ProcessFeatureState::kEnabled;
            }
            anySucceeded = true;
        }

        PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY controlFlowGuardPolicy{};
        if (kGetProcessMitigationPolicy(
            processHandle,
            ProcessControlFlowGuardPolicy,
            &controlFlowGuardPolicy,
            sizeof(controlFlowGuardPolicy)) != FALSE)
        {
            processRecord.controlFlowGuardState = (controlFlowGuardPolicy.EnableControlFlowGuard != 0)
                ? ks::process::ProcessFeatureState::kEnabled
                : ks::process::ProcessFeatureState::kDisabled;
            anySucceeded = true;
        }

        // Hardware-enforced stack protection (Intel CET user-mode shadow stack):
        // - This policy is available starting from Windows 10 20H1; calling it on older systems will fail and leave the state as Unknown.
        PROCESS_MITIGATION_USER_SHADOW_STACK_POLICY userShadowStackPolicy{};
        if (kGetProcessMitigationPolicy(
            processHandle,
            ProcessUserShadowStackPolicy,
            &userShadowStackPolicy,
            sizeof(userShadowStackPolicy)) != FALSE)
        {
            processRecord.hardwareStackProtectionState =
                (userShadowStackPolicy.EnableUserShadowStack != 0U)
                ? ks::process::ProcessFeatureState::kEnabled
                : ks::process::ProcessFeatureState::kDisabled;
            anySucceeded = true;
        }

        return anySucceeded;
    }

    // queryProcessPackageFullName:
    // - Input: A process handle with PROCESS_QUERY_LIMITED_INFORMATION access;
    // - Processing: Read UWP / MSIX package full name;
    // - Return: true indicates success (non-packaged processes also count as success, in which case packageNameOut is empty).
    // Compatibility: GetPackageFullName is available from Windows 8 onwards; it is dynamically resolved and safely skipped on older systems.
    bool queryProcessPackageFullName(const HANDLE processHandle, std::string* const packageNameOut)
    {
        if (processHandle == nullptr || processHandle == INVALID_HANDLE_VALUE || packageNameOut == nullptr)
        {
            return false;
        }
        packageNameOut->clear();

        using GetPackageFullNameFn = LONG(WINAPI*)(HANDLE, UINT32*, PWSTR);
        HMODULE kernel32Module = ::GetModuleHandleW(L"kernel32.dll");
        const auto kGetPackageFullName = reinterpret_cast<GetPackageFullNameFn>(
            kernel32Module != nullptr ? ::GetProcAddress(kernel32Module, "GetPackageFullName") : nullptr);
        if (kGetPackageFullName == nullptr)
        {
            return false;
        }

        // PACKAGE_FULL_NAME_MAX_LENGTH is 127 characters; extra space is reserved here for the null terminator.
        UINT32 nameLength = 128;
        std::wstring nameBuffer(nameLength, L'\0');
        LONG queryResult = kGetPackageFullName(processHandle, &nameLength, nameBuffer.data());
        if (queryResult == ERROR_INSUFFICIENT_BUFFER)
        {
            nameBuffer.assign(nameLength + 1U, L'\0');
            queryResult = kGetPackageFullName(processHandle, &nameLength, nameBuffer.data());
        }

        if (queryResult == ERROR_SUCCESS)
        {
            nameBuffer.resize(::wcsnlen(nameBuffer.c_str(), nameBuffer.size()));
            *packageNameOut = ks::str::utf16ToUtf8(nameBuffer);
            return true;
        }

        // APPMODEL_ERROR_NO_PACKAGE: The target is not a packaged app; this is a definitive conclusion, not a failure.
        return queryResult == APPMODEL_ERROR_NO_PACKAGE;
    }

    // queryProcessDpiAwarenessLevel:
    // - Input: process handle;
    // - Processing: Prefer user32 DPI awareness context APIs to distinguish 'Per-Monitor
    //   V2 / GDI scaling'; fall back to shcore's three-state query otherwise.
    // - Returns: DPI awareness level; returns Unknown if both paths are unavailable.
    ks::process::ProcessDpiAwarenessLevel queryProcessDpiAwarenessLevel(const HANDLE processHandle)
    {
        if (processHandle == nullptr || processHandle == INVALID_HANDLE_VALUE)
        {
            return ks::process::ProcessDpiAwarenessLevel::kUnknown;
        }

        using GetDpiAwarenessContextForProcessFn = DPI_AWARENESS_CONTEXT(WINAPI*)(HANDLE);
        using AreDpiAwarenessContextsEqualFn = BOOL(WINAPI*)(DPI_AWARENESS_CONTEXT, DPI_AWARENESS_CONTEXT);
        HMODULE user32Module = ::GetModuleHandleW(L"user32.dll");
        const auto kGetDpiContextForProcess = reinterpret_cast<GetDpiAwarenessContextForProcessFn>(
            user32Module != nullptr
            ? ::GetProcAddress(user32Module, "GetDpiAwarenessContextForProcess")
            : nullptr);
        const auto kAreDpiContextsEqual = reinterpret_cast<AreDpiAwarenessContextsEqualFn>(
            user32Module != nullptr
            ? ::GetProcAddress(user32Module, "AreDpiAwarenessContextsEqual")
            : nullptr);
        if (kGetDpiContextForProcess != nullptr && kAreDpiContextsEqual != nullptr)
        {
            const DPI_AWARENESS_CONTEXT kDpiContext = kGetDpiContextForProcess(processHandle);
            if (kDpiContext != nullptr)
            {
                // Comparison order proceeds from specific to broad: V2 and GDI scaling belong to more granular contexts and must be evaluated first.
                if (kAreDpiContextsEqual(kDpiContext, DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2) != FALSE)
                {
                    return ks::process::ProcessDpiAwarenessLevel::kPerMonitorAwareV2;
                }
                if (kAreDpiContextsEqual(kDpiContext, DPI_AWARENESS_CONTEXT_UNAWARE_GDISCALED) != FALSE)
                {
                    return ks::process::ProcessDpiAwarenessLevel::kUnawareGdiScaled;
                }
                if (kAreDpiContextsEqual(kDpiContext, DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE) != FALSE)
                {
                    return ks::process::ProcessDpiAwarenessLevel::kPerMonitorAware;
                }
                if (kAreDpiContextsEqual(kDpiContext, DPI_AWARENESS_CONTEXT_SYSTEM_AWARE) != FALSE)
                {
                    return ks::process::ProcessDpiAwarenessLevel::kSystemAware;
                }
                if (kAreDpiContextsEqual(kDpiContext, DPI_AWARENESS_CONTEXT_UNAWARE) != FALSE)
                {
                    return ks::process::ProcessDpiAwarenessLevel::kUnaware;
                }
            }
        }

        // Fallback path: shcore's GetProcessDpiAwareness only distinguishes Unaware / System / PerMonitor.
        using GetProcessDpiAwarenessFn = HRESULT(WINAPI*)(HANDLE, PROCESS_DPI_AWARENESS*);
        HMODULE shcoreModule = ::GetModuleHandleW(L"shcore.dll");
        if (shcoreModule == nullptr)
        {
            shcoreModule = ::LoadLibraryW(L"shcore.dll");
        }
        const auto kGetProcessDpiAwareness = reinterpret_cast<GetProcessDpiAwarenessFn>(
            shcoreModule != nullptr ? ::GetProcAddress(shcoreModule, "GetProcessDpiAwareness") : nullptr);
        if (kGetProcessDpiAwareness == nullptr)
        {
            return ks::process::ProcessDpiAwarenessLevel::kUnknown;
        }

        PROCESS_DPI_AWARENESS awarenessValue = PROCESS_DPI_UNAWARE;
        if (FAILED(kGetProcessDpiAwareness(processHandle, &awarenessValue)))
        {
            return ks::process::ProcessDpiAwarenessLevel::kUnknown;
        }
        switch (awarenessValue)
        {
        case PROCESS_SYSTEM_DPI_AWARE:
            return ks::process::ProcessDpiAwarenessLevel::kSystemAware;
        case PROCESS_PER_MONITOR_DPI_AWARE:
            return ks::process::ProcessDpiAwarenessLevel::kPerMonitorAware;
        case PROCESS_DPI_UNAWARE:
        default:
            return ks::process::ProcessDpiAwarenessLevel::kUnaware;
        }
    }

    // queryFileSignatureInfo:
    // - Use WinVerifyTrust to determine if the file is 'trusted by Windows'.
    // - Parse the signature chain to obtain the publisher.
    // - Build unified display text for direct presentation in tables and detail windows.
    FileSignatureInfo queryFileSignatureInfo(const std::string& utf8Path)
    {
        FileSignatureInfo signatureInfo{};
        signatureInfo.displayText = "Unknown";

        if (utf8Path.empty())
        {
            return signatureInfo;
        }

        const std::wstring kUtf16Path = ks::str::utf8ToUtf16(utf8Path);
        if (kUtf16Path.empty())
        {
            return signatureInfo;
        }

        WINTRUST_FILE_INFO fileInfo{};
        fileInfo.cbStruct = sizeof(fileInfo);
        fileInfo.pcwszFilePath = kUtf16Path.c_str();

        WINTRUST_DATA trustData{};
        trustData.cbStruct = sizeof(trustData);
        trustData.dwUIChoice = WTD_UI_NONE;
        trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
        trustData.dwUnionChoice = WTD_CHOICE_FILE;
        trustData.pFile = &fileInfo;
        trustData.dwStateAction = WTD_STATEACTION_VERIFY;
        trustData.dwProvFlags = WTD_SAFER_FLAG | WTD_CACHE_ONLY_URL_RETRIEVAL;

        GUID policyGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        const LONG kVerifyResult = ::WinVerifyTrust(nullptr, &policyGuid, &trustData);

        // Attempt to extract the publisher name (vendor) via the signature chain.
        if (trustData.hWVTStateData != nullptr)
        {
            CRYPT_PROVIDER_DATA* providerData = ::WTHelperProvDataFromStateData(trustData.hWVTStateData);
            if (providerData != nullptr)
            {
                CRYPT_PROVIDER_SGNR* signer = ::WTHelperGetProvSignerFromChain(providerData, 0, FALSE, 0);
                if (signer != nullptr && signer->csCertChain > 0 && signer->pasCertChain != nullptr)
                {
                    const CERT_CONTEXT* certificateContext = signer->pasCertChain[0].pCert;
                    if (certificateContext != nullptr)
                    {
                        wchar_t publisherBuffer[512] = {};
                        const DWORD kPublisherLength = ::CertGetNameStringW(
                            certificateContext,
                            CERT_NAME_SIMPLE_DISPLAY_TYPE,
                            0,
                            nullptr,
                            publisherBuffer,
                            static_cast<DWORD>(std::size(publisherBuffer)));
                        if (kPublisherLength > 1)
                        {
                            signatureInfo.publisher = ks::str::utf16ToUtf8(publisherBuffer);
                        }
                    }
                }
            }
        }

        // Regardless of the verification result, the WinVerifyTrust state handle must be closed to prevent a leak.
        trustData.dwStateAction = WTD_STATEACTION_CLOSE;
        ::WinVerifyTrust(nullptr, &policyGuid, &trustData);

        // If the publisher cannot be retrieved from the certificate chain, fall back to the file version's CompanyName.
        if (signatureInfo.publisher.empty())
        {
            signatureInfo.publisher = queryCompanyNameByVersion(kUtf16Path);
        }
        signatureInfo.publisher = ks::str::trimCopy(signatureInfo.publisher);

        if (kVerifyResult == ERROR_SUCCESS)
        {
            signatureInfo.hasSignature = true;
            signatureInfo.trustedByWindows = true;
            if (signatureInfo.publisher.empty())
            {
                signatureInfo.publisher = "Unknown Publisher";
            }
            signatureInfo.displayText = signatureInfo.publisher + " (Trusted)";
            return signatureInfo;
        }

        if (kVerifyResult == TRUST_E_NOSIGNATURE || kVerifyResult == TRUST_E_SUBJECT_FORM_UNKNOWN)
        {
            signatureInfo.hasSignature = false;
            signatureInfo.trustedByWindows = false;
            signatureInfo.displayText = "Unsigned";
            return signatureInfo;
        }

        // Other failure codes are uniformly treated as 'signed but untrusted'.
        signatureInfo.hasSignature = true;
        signatureInfo.trustedByWindows = false;
        if (signatureInfo.publisher.empty())
        {
            signatureInfo.publisher = "Unknown Publisher";
        }
        signatureInfo.displayText = signatureInfo.publisher + " (Untrusted)";
        return signatureInfo;
    }

    // readRemoteMemoryExact：
    // - Read a fixed length of memory from the target process.
    // - Input processHandle: Handle to the target process; remoteAddress: Remote address.
    // - Input localBuffer/localSize: local buffer.
    // - Returns true if exactly localSize bytes are read successfully; returns false on failure or partial read.
    bool readRemoteMemoryExact(
        const HANDLE processHandle,
        const std::uint64_t remoteAddress,
        void* localBuffer,
        const SIZE_T localSize)
    {
        if (processHandle == nullptr || remoteAddress == 0 || localBuffer == nullptr || localSize == 0)
        {
            return false;
        }

        SIZE_T bytesRead = 0;
        const BOOL kReadOk = ::ReadProcessMemory(
            processHandle,
            reinterpret_cast<LPCVOID>(static_cast<std::uintptr_t>(remoteAddress)),
            localBuffer,
            localSize,
            &bytesRead);
        return kReadOk != FALSE && bytesRead == localSize;
    }

    // readRemoteStructure：
    // - Template-based reading of remote structures;
    // - Note: Clear the output structure before reading; callers will not see dirty data on failure.
    // - Returns true to indicate the structure was read successfully.
    template<typename T>
    bool readRemoteStructure(
        const HANDLE processHandle,
        const std::uint64_t remoteAddress,
        T& valueOut)
    {
        std::memset(&valueOut, 0, sizeof(T));
        return readRemoteMemoryExact(
            processHandle,
            remoteAddress,
            &valueOut,
            static_cast<SIZE_T>(sizeof(T)));
    }

    // readRemoteUnicodeStringByAddress：
    // - Reads a string via a remote UTF-16 address and byte length.
    // - Validates Length for evenness and upper bound to prevent corrupted fields in the target process from crashing the enumeration thread;
    // - Returns UTF-8 text; returns an empty string on failure.
    std::string readRemoteUnicodeStringByAddress(
        const HANDLE processHandle,
        const std::uint64_t bufferAddress,
        const USHORT lengthBytes)
    {
        if (processHandle == nullptr || bufferAddress == 0 || lengthBytes == 0)
        {
            return std::string();
        }
        if ((lengthBytes % sizeof(wchar_t)) != 0 ||
            static_cast<std::size_t>(lengthBytes) > kRemoteUnicodeStringMaxBytes)
        {
            return std::string();
        }

        std::wstring textBuffer(
            static_cast<std::size_t>(lengthBytes / sizeof(wchar_t)),
            L'\0');
        SIZE_T bytesRead = 0;
        const BOOL kReadOk = ::ReadProcessMemory(
            processHandle,
            reinterpret_cast<LPCVOID>(static_cast<std::uintptr_t>(bufferAddress)),
            textBuffer.data(),
            static_cast<SIZE_T>(lengthBytes),
            &bytesRead);
        if (kReadOk == FALSE || bytesRead < sizeof(wchar_t))
        {
            return std::string();
        }

        const std::size_t kCharCount = static_cast<std::size_t>(
            std::min<SIZE_T>(bytesRead, static_cast<SIZE_T>(lengthBytes)) / sizeof(wchar_t));
        if (kCharCount < textBuffer.size())
        {
            textBuffer.resize(kCharCount);
        }
        return ks::str::utf16ToUtf8(textBuffer);
    }

    // readRemoteUnicodeString64：
    // - Read UNICODE_STRING from a 64-bit target;
    // - Input remoteUnicode: snapshot copied from a remote structure.
    // - Returns UTF-8 text; returns an empty string on failure.
    std::string readRemoteUnicodeString64(
        const HANDLE processHandle,
        const UNICODE_STRING& remoteUnicode)
    {
        return readRemoteUnicodeStringByAddress(
            processHandle,
            reinterpret_cast<std::uint64_t>(remoteUnicode.Buffer),
            remoteUnicode.Length);
    }

    // readRemoteUnicodeString32：
    // - Read UNICODE_STRING from a 32-bit target;
    // - Input remoteUnicode uses a manual 32-bit layout to avoid pointer width misalignment;
    // - Returns UTF-8 text; returns an empty string on failure.
    std::string readRemoteUnicodeString32(
        const HANDLE processHandle,
        const RemoteUnicodeString32& remoteUnicode)
    {
        return readRemoteUnicodeStringByAddress(
            processHandle,
            static_cast<std::uint64_t>(remoteUnicode.buffer),
            remoteUnicode.length);
    }

    // queryProcessCommandLineByNtInfo：
    // - Use ProcessCommandLineInformation to query the command line.
    // - On newer systems, directly return the UNICODE_STRING plus the string buffer.
    // - Returns UTF-8 text; on failure, returns an empty string and falls back to the PEB path.
    std::string queryProcessCommandLineByNtInfo(
        const NtQueryInformationProcessFn ntQueryInformationProcess,
        const HANDLE processHandle)
    {
        if (ntQueryInformationProcess == nullptr || processHandle == nullptr)
        {
            return std::string();
        }

        ULONG requiredLength = 0;
        NTSTATUS firstStatus = ntQueryInformationProcess(
            processHandle,
            kProcessCommandLineInformationClass,
            nullptr,
            0,
            &requiredLength);
        if (!NT_SUCCESS(firstStatus) && requiredLength == 0)
        {
            return std::string();
        }
        if (requiredLength < sizeof(UNICODE_STRING))
        {
            requiredLength = static_cast<ULONG>(sizeof(UNICODE_STRING) + 512);
        }

        std::vector<std::uint8_t> queryBuffer(requiredLength + sizeof(wchar_t), 0);
        NTSTATUS secondStatus = ntQueryInformationProcess(
            processHandle,
            kProcessCommandLineInformationClass,
            queryBuffer.data(),
            static_cast<ULONG>(queryBuffer.size()),
            &requiredLength);
        if (!NT_SUCCESS(secondStatus))
        {
            return std::string();
        }

        const auto* commandUnicode = reinterpret_cast<const UNICODE_STRING*>(queryBuffer.data());
        if (commandUnicode == nullptr || commandUnicode->Length == 0 || commandUnicode->Buffer == nullptr)
        {
            return std::string();
        }

        const std::uintptr_t kBufferBegin = reinterpret_cast<std::uintptr_t>(queryBuffer.data());
        const std::uintptr_t kBufferSize = queryBuffer.size();
        const std::uintptr_t kTextPtr = reinterpret_cast<std::uintptr_t>(commandUnicode->Buffer);
        const std::size_t kTextBytes = static_cast<std::size_t>(commandUnicode->Length);
        if ((kTextBytes % sizeof(wchar_t)) != 0 || kTextBytes > kRemoteUnicodeStringMaxBytes)
        {
            return std::string();
        }

        if (kTextPtr >= kBufferBegin &&
            kTextPtr - kBufferBegin <= kBufferSize &&
            kTextBytes <= kBufferSize - (kTextPtr - kBufferBegin))
        {
            const auto* wideText = reinterpret_cast<const wchar_t*>(kTextPtr);
            return ks::str::utf16ToUtf8(std::wstring(
                wideText,
                wideText + static_cast<std::size_t>(commandUnicode->Length / sizeof(wchar_t))));
        }

        return readRemoteUnicodeString64(processHandle, *commandUnicode);
    }

    // queryProcessCommandLineByPeb64：
    // - Read ProcessParameters.CommandLine according to the 64-bit PEB layout;
    // - Fallback mechanism used when ProcessCommandLineInformation fails.
    // - Returns UTF-8 text; returns an empty string on failure.
    std::string queryProcessCommandLineByPeb64(
        const HANDLE processHandle,
        const std::uint64_t pebAddress)
    {
        Peb64CommandLineLite pebSnapshot{};
        if (!readRemoteStructure(processHandle, pebAddress, pebSnapshot) ||
            pebSnapshot.processParameters == nullptr)
        {
            return std::string();
        }

        RtlUserProcessParameters64CommandLine processParameters{};
        if (!readRemoteStructure(
            processHandle,
            reinterpret_cast<std::uint64_t>(pebSnapshot.processParameters),
            processParameters))
        {
            return std::string();
        }

        return readRemoteUnicodeString64(processHandle, processParameters.commandLine);
    }

    // queryProcessCommandLineByPeb32：
    // - Read ProcessParameters.CommandLine according to the 32-bit Wow64 PEB layout;
    // - Fixes structure offset misalignment when the x64 controlling process reads a 32-bit target.
    // - Returns UTF-8 text; returns an empty string on failure.
    std::string queryProcessCommandLineByPeb32(
        const HANDLE processHandle,
        const std::uint64_t pebAddress)
    {
        Peb32CommandLineLite pebSnapshot{};
        if (!readRemoteStructure(processHandle, pebAddress, pebSnapshot) ||
            pebSnapshot.processParameters == 0)
        {
            return std::string();
        }

        RtlUserProcessParameters32CommandLine processParameters{};
        if (!readRemoteStructure(
            processHandle,
            static_cast<std::uint64_t>(pebSnapshot.processParameters),
            processParameters))
        {
            return std::string();
        }

        return readRemoteUnicodeString32(processHandle, processParameters.commandLine);
    }

    // Read the command line from a remote process (by reading PEB / ProcessParameters).
    std::string queryProcessCommandLineByHandle(const HANDLE processHandle)
    {
        // Command-line read order:
        // 1) Prefer ProcessCommandLineInformation to let the system handle structural differences;
        // 2) Re-read Native PEB to override old systems or restricted information classes;
        // 3) Finally read the Wow64 PEB to fix offset misalignment when x64 tools read 32-bit targets.
        const auto kNtQueryInformationProcess = reinterpret_cast<NtQueryInformationProcessFn>(
            getNtdllProcAddress("NtQueryInformationProcess"));
        if (kNtQueryInformationProcess == nullptr)
        {
            return std::string();
        }

        const std::string kCommandLineByInfo = queryProcessCommandLineByNtInfo(
            kNtQueryInformationProcess,
            processHandle);
        if (!kCommandLineByInfo.empty())
        {
            return kCommandLineByInfo;
        }

        ProcessBasicInformationLocal basicInfo{};
        NTSTATUS queryStatus = kNtQueryInformationProcess(
            processHandle,
            ProcessBasicInformation,
            &basicInfo,
            static_cast<ULONG>(sizeof(basicInfo)),
            nullptr);
        if (!NT_SUCCESS(queryStatus) || basicInfo.pebBaseAddress == nullptr)
        {
            return std::string();
        }

        const std::string kCommandLineByNativePeb = queryProcessCommandLineByPeb64(
            processHandle,
            reinterpret_cast<std::uint64_t>(basicInfo.pebBaseAddress));
        if (!kCommandLineByNativePeb.empty())
        {
            return kCommandLineByNativePeb;
        }

        ULONG_PTR wow64PebAddress = 0;
        NTSTATUS wow64Status = kNtQueryInformationProcess(
            processHandle,
            kProcessWow64InformationClass,
            &wow64PebAddress,
            static_cast<ULONG>(sizeof(wow64PebAddress)),
            nullptr);
        if (NT_SUCCESS(wow64Status) &&
            wow64PebAddress != 0 &&
            wow64PebAddress != reinterpret_cast<ULONG_PTR>(basicInfo.pebBaseAddress))
        {
            return queryProcessCommandLineByPeb32(
                processHandle,
                static_cast<std::uint64_t>(wow64PebAddress));
        }

        return std::string();
    }

    // Convert PID to DWORD to unify types and avoid implicit narrowing warnings.
    DWORD toDwordPid(const std::uint32_t pid)
    {
        return static_cast<DWORD>(pid);
    }

    // Extract filename from path (fallback for process name).
    std::string extractFileNameFromPath(const std::string& utf8Path)
    {
        if (utf8Path.empty())
        {
            return std::string();
        }
        const std::size_t kLastSlash = utf8Path.find_last_of("\\/");
        if (kLastSlash == std::string::npos)
        {
            return utf8Path;
        }
        return utf8Path.substr(kLastSlash + 1);
    }

    // Convert process priority constants to readable text.
    std::string priorityClassToText(const DWORD priorityClass)
    {
        switch (priorityClass)
        {
        case IDLE_PRIORITY_CLASS:
            return "Idle";
        case BELOW_NORMAL_PRIORITY_CLASS:
            return "BelowNormal";
        case NORMAL_PRIORITY_CLASS:
            return "Normal";
        case ABOVE_NORMAL_PRIORITY_CLASS:
            return "AboveNormal";
        case HIGH_PRIORITY_CLASS:
            return "High";
        case REALTIME_PRIORITY_CLASS:
            return "Realtime";
        default:
            return "Unknown";
        }
    }

    // Query the current process priority text.
    std::string queryPriorityTextByHandle(const HANDLE processHandle)
    {
        const DWORD kPriorityClass = ::GetPriorityClass(processHandle);
        if (kPriorityClass == 0)
        {
            return "Unknown";
        }
        return priorityClassToText(kPriorityClass);
    }
    // ProcessPowerThrottlingStateNative：
    // - Native structure declaration compatible with older SDKs;
    // - The ExecutionSpeed bit in controlMask/stateMask represents Windows Efficiency Mode.
    struct ProcessPowerThrottlingStateNative
    {
        ULONG version = 0;
        ULONG controlMask = 0;
        ULONG stateMask = 0;
    };

    // ProcessProtectionLevelInformationNative：
    // - Native structure declaration compatible with older SDKs;
    // - protectionLevel: stores the PROTECTION_LEVEL_* enumeration.
    struct ProcessProtectionLevelInformationNative
    {
        DWORD protectionLevel = 0;
    };

    // processProtectionLevelToText purpose: Translate public enum values into UI-readable text.
    std::string processProtectionLevelToText(const DWORD protectionLevel)
    {
        // protectionLevel: The original enum value returned by GetProcessInformation.
        // Return value: Includes the name and hexadecimal value for easy comparison with WinAPI documentation.
        switch (protectionLevel)
        {
        case kProcessProtectionLevelNone:
            return "None (PROTECTION_LEVEL_NONE, 0xFFFFFFFE)";
        case kProcessProtectionLevelWinTcbLight:
            return "WinTcbLight (PROTECTION_LEVEL_WINTCB_LIGHT, 0x00000000)";
        case kProcessProtectionLevelWindows:
            return "Windows (PROTECTION_LEVEL_WINDOWS, 0x00000001)";
        case kProcessProtectionLevelWindowsLight:
            return "WindowsLight (PROTECTION_LEVEL_WINDOWS_LIGHT, 0x00000002)";
        case kProcessProtectionLevelAntimalwareLight:
            return "AntimalwareLight (PROTECTION_LEVEL_ANTIMALWARE_LIGHT, 0x00000003)";
        case kProcessProtectionLevelLsaLight:
            return "LsaLight (PROTECTION_LEVEL_LSA_LIGHT, 0x00000004)";
        case kProcessProtectionLevelWinTcb:
            return "WinTcb (PROTECTION_LEVEL_WINTCB, 0x00000005)";
        case kProcessProtectionLevelCodegenLight:
            return "CodegenLight (PROTECTION_LEVEL_CODEGEN_LIGHT, 0x00000006)";
        case kProcessProtectionLevelAuthenticode:
            return "Authenticode (PROTECTION_LEVEL_AUTHENTICODE, 0x00000007)";
        case kProcessProtectionLevelPplApp:
            return "PplApp (PROTECTION_LEVEL_PPL_APP, 0x00000008)";
        case kProcessProtectionLevelSame:
            return "Same (PROTECTION_LEVEL_SAME, 0xFFFFFFFF)";
        default:
            break;
        }

        std::ostringstream textBuilder;
        textBuilder << "Unknown (0x"
            << std::hex
            << std::uppercase
            << std::setw(8)
            << std::setfill('0')
            << static_cast<unsigned long>(protectionLevel)
            << ")";
        return textBuilder.str();
    }

    // queryProcessEfficiencyModeByHandle purpose: read the efficiency mode status of the target process.
    bool queryProcessEfficiencyModeByHandle(
        const HANDLE processHandle,
        bool* const enabledOut,
        std::string* const errorMessage)
    {
        if (enabledOut != nullptr)
        {
            *enabledOut = false;
        }
        if (processHandle == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "Process handle is null.";
            }
            return false;
        }

        HMODULE kernel32Module = ::GetModuleHandleW(L"kernel32.dll");
        const auto kGetProcessInformation = reinterpret_cast<GetProcessInformationFn>(
            kernel32Module != nullptr ? ::GetProcAddress(kernel32Module, "GetProcessInformation") : nullptr);
        if (kGetProcessInformation == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "GetProcessInformation(ProcessPowerThrottling) is not available.";
            }
            return false;
        }

        ProcessPowerThrottlingStateNative powerState{};
        powerState.version = kProcessPowerThrottlingCurrentVersion;
        const BOOL kQueryOk = kGetProcessInformation(
            processHandle,
            kProcessPowerThrottlingInfoClass,
            &powerState,
            static_cast<DWORD>(sizeof(powerState)));
        if (kQueryOk == FALSE)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "GetProcessInformation(ProcessPowerThrottling) failed: "
                    + formatLastErrorMessage(::GetLastError());
            }
            return false;
        }

        if (enabledOut != nullptr)
        {
            *enabledOut =
                (powerState.controlMask & kProcessPowerThrottlingExecutionSpeed) != 0 &&
                (powerState.stateMask & kProcessPowerThrottlingExecutionSpeed) != 0;
        }
        return true;
    }


    // Convert machine constants to architecture text.
    std::string machineToArchitectureText(const USHORT machineType)
    {
        switch (machineType)
        {
        case IMAGE_FILE_MACHINE_AMD64:
            return "x64";
        case IMAGE_FILE_MACHINE_I386:
            return "x86";
        case IMAGE_FILE_MACHINE_ARM64:
            return "ARM64";
        case IMAGE_FILE_MACHINE_ARM:
            return "ARM";
        default:
            return "Unknown";
        }
    }

    // Query target process architecture (prefer IsWow64Process2).
    std::string queryProcessArchitectureByHandle(const HANDLE processHandle)
    {
        using IsWow64Process2Fn = BOOL(WINAPI*)(HANDLE, USHORT*, USHORT*);
        const HMODULE kKernel32Module = ::GetModuleHandleW(L"kernel32.dll");
        const auto kIsWow64Process2Fn = kKernel32Module != nullptr
            ? reinterpret_cast<IsWow64Process2Fn>(::GetProcAddress(kKernel32Module, "IsWow64Process2"))
            : nullptr;
        if (kIsWow64Process2Fn != nullptr)
        {
            USHORT processMachine = IMAGE_FILE_MACHINE_UNKNOWN;
            USHORT nativeMachine = IMAGE_FILE_MACHINE_UNKNOWN;
            if (kIsWow64Process2Fn(processHandle, &processMachine, &nativeMachine) != FALSE)
            {
                // processMachine=UNKNOWN indicates 'Consistent with the system's native architecture'.
                if (processMachine == IMAGE_FILE_MACHINE_UNKNOWN)
                {
                    return machineToArchitectureText(nativeMachine);
                }
                return machineToArchitectureText(processMachine);
            }
        }

        // Fallback to the legacy API: can only distinguish between WOW64 x86 and 'non-WOW64'.
        BOOL isWow64Process = FALSE;
        if (::IsWow64Process(processHandle, &isWow64Process) == FALSE)
        {
            return "Unknown";
        }

#if defined(_WIN64)
        return isWow64Process ? "x86" : "x64";
#else
        return isWow64Process ? "x86" : "x86";
#endif
    }

    // Reads the PE header and returns AddressOfEntryPoint (RVA).
    std::uint32_t queryImageEntryPointRvaByPath(const std::string& modulePath)
    {
        if (modulePath.empty())
        {
            return 0;
        }

        std::ifstream moduleFile(modulePath, std::ios::binary);
        if (!moduleFile.is_open())
        {
            return 0;
        }

        IMAGE_DOS_HEADER dosHeader{};
        moduleFile.read(reinterpret_cast<char*>(&dosHeader), sizeof(dosHeader));
        if (!moduleFile.good() || dosHeader.e_magic != IMAGE_DOS_SIGNATURE)
        {
            return 0;
        }

        moduleFile.seekg(static_cast<std::streamoff>(dosHeader.e_lfanew), std::ios::beg);
        DWORD ntSignature = 0;
        moduleFile.read(reinterpret_cast<char*>(&ntSignature), sizeof(ntSignature));
        if (!moduleFile.good() || ntSignature != IMAGE_NT_SIGNATURE)
        {
            return 0;
        }

        IMAGE_FILE_HEADER fileHeader{};
        moduleFile.read(reinterpret_cast<char*>(&fileHeader), sizeof(fileHeader));
        if (!moduleFile.good())
        {
            return 0;
        }

        WORD optionalMagic = 0;
        moduleFile.read(reinterpret_cast<char*>(&optionalMagic), sizeof(optionalMagic));
        if (!moduleFile.good())
        {
            return 0;
        }
        moduleFile.seekg(-static_cast<std::streamoff>(sizeof(optionalMagic)), std::ios::cur);

        if (optionalMagic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        {
            IMAGE_OPTIONAL_HEADER64 optionalHeader{};
            moduleFile.read(reinterpret_cast<char*>(&optionalHeader), sizeof(optionalHeader));
            if (!moduleFile.good())
            {
                return 0;
            }
            return optionalHeader.AddressOfEntryPoint;
        }

        if (optionalMagic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
        {
            IMAGE_OPTIONAL_HEADER32 optionalHeader{};
            moduleFile.read(reinterpret_cast<char*>(&optionalHeader), sizeof(optionalHeader));
            if (!moduleFile.good())
            {
                return 0;
            }
            return optionalHeader.AddressOfEntryPoint;
        }

        return 0;
    }

    // Compress the thread ID list into a string to avoid overly long cells.
    std::string buildThreadIdSummaryText(const std::vector<std::uint32_t>& threadIds)
    {
        if (threadIds.empty())
        {
            return "-";
        }

        constexpr std::size_t kMaxDisplayCount = 8;
        std::ostringstream stream;
        const std::size_t kDisplayCount = std::min(kMaxDisplayCount, threadIds.size());
        for (std::size_t index = 0; index < kDisplayCount; ++index)
        {
            if (index > 0)
            {
                stream << ", ";
            }
            stream << threadIds[index];
        }
        if (threadIds.size() > kMaxDisplayCount)
        {
            stream << " ... (+" << (threadIds.size() - kMaxDisplayCount) << ")";
        }
        return stream.str();
    }

    // Whether the path points to a directory.
    bool isDirectoryPath(const std::string& utf8Path)
    {
        if (utf8Path.empty())
        {
            return false;
        }

        const std::wstring kUtf16Path = ks::str::utf8ToUtf16(utf8Path);
        if (kUtf16Path.empty())
        {
            return false;
        }

        std::error_code errorCode;
        return std::filesystem::is_directory(std::filesystem::path(kUtf16Path), errorCode);
    }

    // Open the folder in Explorer or locate the file.
    bool openInExplorerByPath(const std::string& targetPath, std::string* const errorMessage)
    {
        if (targetPath.empty())
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "Target path is empty.";
            }
            return false;
        }

        const std::wstring kUtf16Path = ks::str::utf8ToUtf16(targetPath);
        if (kUtf16Path.empty())
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "Path UTF-8 -> UTF-16 conversion failed.";
            }
            return false;
        }

        HINSTANCE shellResult = nullptr;
        if (isDirectoryPath(targetPath))
        {
            shellResult = ::ShellExecuteW(
                nullptr,
                L"open",
                kUtf16Path.c_str(),
                nullptr,
                nullptr,
                SW_SHOWNORMAL);
        }
        else
        {
            std::wstring parameters = L"/select,\"" + kUtf16Path + L"\"";
            shellResult = ::ShellExecuteW(
                nullptr,
                L"open",
                L"explorer.exe",
                parameters.c_str(),
                nullptr,
                SW_SHOWNORMAL);
        }

        if (reinterpret_cast<std::intptr_t>(shellResult) > 32)
        {
            return true;
        }

        if (errorMessage != nullptr)
        {
            std::ostringstream stream;
            stream << "ShellExecute(explorer) failed, code=" << reinterpret_cast<std::intptr_t>(shellResult);
            *errorMessage = stream.str();
        }
        return false;
    }

    // Unified default token access mask (used for the "open by PID and create new process" scenario).
    constexpr DWORD kDefaultTokenDesiredAccess =
        TOKEN_QUERY |
        TOKEN_DUPLICATE |
        TOKEN_ASSIGN_PRIMARY |
        TOKEN_ADJUST_PRIVILEGES |
        TOKEN_ADJUST_DEFAULT |
        TOKEN_ADJUST_SESSIONID;

    // Convert between 64-bit integers and HANDLE to avoid repeated reinterpret_cast.
    HANDLE uint64ToHandle(const std::uint64_t rawValue)
    {
        return reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(rawValue));
    }

    std::uint64_t handleToUint64(const HANDLE handleValue)
    {
        return static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(handleValue));
    }

    // Convert multi-line KEY=VALUE input from the UI into a Unicode environment block terminated by two \0 characters.
    // Input: entries is UTF-8 text, where each element represents an environment variable.
    // Processing: Skip blank lines and conversion failures, then concatenate per Win32 requirements into "A=B\0C=D\0\0".
    // Return: full environment block if at least one valid entry exists; empty vector if no valid entries, allowing the caller to pass nullptr.
    std::vector<wchar_t> buildUnicodeEnvironmentBlock(const std::vector<std::string>& entries)
    {
        std::vector<wchar_t> environmentBlock;
        bool hasEntry = false;
        for (const std::string& entryText : entries)
        {
            const std::string kTrimmedEntry = ks::str::trimCopy(entryText);
            if (kTrimmedEntry.empty())
            {
                continue;
            }

            const std::wstring kWideEntry = ks::str::utf8ToUtf16(kTrimmedEntry);
            if (kWideEntry.empty())
            {
                continue;
            }

            environmentBlock.insert(environmentBlock.end(), kWideEntry.begin(), kWideEntry.end());
            environmentBlock.push_back(L'\0');
            hasEntry = true;
        }

        if (!hasEntry)
        {
            return std::vector<wchar_t>();
        }

        // The environment block must end with two \0 terminators. Each variable already has one \0; append the final one here.
        environmentBlock.push_back(L'\0');
        return environmentBlock;
    }

    // Convert multi-line KEY=VALUE input from the UI into a Unicode environment block terminated by two \0 characters.
    // Input: entries is UTF-8 text, where each element represents an environment variable.
    // Handling: Convert to UTF-16 first, then convert to narrow bytes using the system ANSI code page, matching the Win32 semantics for processes not created with CREATE_UNICODE_ENVIRONMENT.
    // Returns: a complete environment block if at least one valid entry exists; an empty vector if no valid entries exist or conversion fails, allowing the caller to pass nullptr.
    std::vector<char> buildAnsiEnvironmentBlock(const std::vector<std::string>& entries)
    {
        std::vector<char> environmentBlock;
        bool hasEntry = false;
        for (const std::string& entryText : entries)
        {
            const std::string kTrimmedEntry = ks::str::trimCopy(entryText);
            if (kTrimmedEntry.empty())
            {
                continue;
            }

            const std::wstring kWideEntry = ks::str::utf8ToUtf16(kTrimmedEntry);
            if (kWideEntry.empty())
            {
                continue;
            }

            const int kAnsiLengthWithNull = ::WideCharToMultiByte(
                CP_ACP,
                0,
                kWideEntry.c_str(),
                -1,
                nullptr,
                0,
                nullptr,
                nullptr);
            if (kAnsiLengthWithNull <= 1)
            {
                continue;
            }

            std::vector<char> ansiEntry(static_cast<std::size_t>(kAnsiLengthWithNull), '\0');
            const int kConvertedLengthWithNull = ::WideCharToMultiByte(
                CP_ACP,
                0,
                kWideEntry.c_str(),
                -1,
                ansiEntry.data(),
                kAnsiLengthWithNull,
                nullptr,
                nullptr);
            if (kConvertedLengthWithNull <= 1)
            {
                continue;
            }

            environmentBlock.insert(
                environmentBlock.end(),
                ansiEntry.begin(),
                ansiEntry.end() - 1);
            environmentBlock.push_back('\0');
            hasEntry = true;
        }

        if (!hasEntry)
        {
            return std::vector<char>();
        }

        // The environment block must end with two \0 terminators. Each variable already has one \0; append the final one here.
        environmentBlock.push_back('\0');
        return environmentBlock;
    }

    // SECURITY_ATTRIBUTES construction: false indicates the caller layer should pass nullptr.
    bool buildSecurityAttributes(
        const ks::process::SecurityAttributesInput& inputValue,
        SECURITY_ATTRIBUTES& outputValue)
    {
        if (!inputValue.useValue)
        {
            return false;
        }

        outputValue = {};
        outputValue.nLength = inputValue.nLength == 0
            ? static_cast<DWORD>(sizeof(SECURITY_ATTRIBUTES))
            : static_cast<DWORD>(inputValue.nLength);
        outputValue.lpSecurityDescriptor = reinterpret_cast<LPVOID>(
            static_cast<std::uintptr_t>(inputValue.securityDescriptor));
        outputValue.bInheritHandle = inputValue.inheritHandle ? TRUE : FALSE;
        return true;
    }

    // STARTUPINFOW string buffer, ensuring pointer validity during CreateProcess calls.
    struct StartupInfoBufferSet
    {
        std::wstring reservedText;
        std::wstring desktopText;
        std::wstring titleText;
    };

    // STARTUPINFOW construction: CreateProcess* always requires a valid structure; use default zero-initialized values if not customized.
    void buildStartupInfo(
        const ks::process::StartupInfoInput& inputValue,
        STARTUPINFOW& outputValue,
        StartupInfoBufferSet& bufferSet)
    {
        outputValue = {};
        outputValue.cb = (!inputValue.useValue || inputValue.cb == 0)
            ? static_cast<DWORD>(sizeof(STARTUPINFOW))
            : static_cast<DWORD>(inputValue.cb);
        if (!inputValue.useValue)
        {
            return;
        }

        if (!inputValue.lpReserved.empty())
        {
            bufferSet.reservedText = ks::str::utf8ToUtf16(inputValue.lpReserved);
            if (!bufferSet.reservedText.empty())
            {
                outputValue.lpReserved = bufferSet.reservedText.data();
            }
        }
        if (!inputValue.lpDesktop.empty())
        {
            bufferSet.desktopText = ks::str::utf8ToUtf16(inputValue.lpDesktop);
            if (!bufferSet.desktopText.empty())
            {
                outputValue.lpDesktop = bufferSet.desktopText.data();
            }
        }
        if (!inputValue.lpTitle.empty())
        {
            bufferSet.titleText = ks::str::utf8ToUtf16(inputValue.lpTitle);
            if (!bufferSet.titleText.empty())
            {
                outputValue.lpTitle = bufferSet.titleText.data();
            }
        }

        outputValue.dwX = static_cast<DWORD>(inputValue.dwX);
        outputValue.dwY = static_cast<DWORD>(inputValue.dwY);
        outputValue.dwXSize = static_cast<DWORD>(inputValue.dwXSize);
        outputValue.dwYSize = static_cast<DWORD>(inputValue.dwYSize);
        outputValue.dwXCountChars = static_cast<DWORD>(inputValue.dwXCountChars);
        outputValue.dwYCountChars = static_cast<DWORD>(inputValue.dwYCountChars);
        outputValue.dwFillAttribute = static_cast<DWORD>(inputValue.dwFillAttribute);
        outputValue.dwFlags = static_cast<DWORD>(inputValue.dwFlags);
        outputValue.wShowWindow = static_cast<WORD>(inputValue.wShowWindow);
        outputValue.cbReserved2 = static_cast<WORD>(inputValue.cbReserved2);
        outputValue.lpReserved2 = reinterpret_cast<LPBYTE>(
            static_cast<std::uintptr_t>(inputValue.lpReserved2));
        outputValue.hStdInput = uint64ToHandle(inputValue.hStdInput);
        outputValue.hStdOutput = uint64ToHandle(inputValue.hStdOutput);
        outputValue.hStdError = uint64ToHandle(inputValue.hStdError);
    }

    // PROCESS_INFORMATION is the output buffer for CreateProcess*; a valid, zero-initialized address must be provided before calling.
    void initializeProcessInformationOutput(PROCESS_INFORMATION& outputValue)
    {
        outputValue = {};
    }

    // Open the process token for the specified PID.
    bool openTokenByProcessPid(
        const std::uint32_t pid,
        const DWORD desiredAccess,
        HANDLE& tokenOut,
        std::string* const errorMessage)
    {
        tokenOut = nullptr;
        if (pid == 0)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "tokenSourcePid cannot be 0.";
            }
            return false;
        }

        const HANDLE kProcessHandle = ::OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION,
            FALSE,
            toDwordPid(pid));
        if (kProcessHandle == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "OpenProcess(for token) failed: " + formatLastErrorMessage(::GetLastError());
            }
            return false;
        }

        const BOOL kOpenTokenOk = ::OpenProcessToken(kProcessHandle, desiredAccess, &tokenOut);
        const DWORD kOpenTokenError = ::GetLastError();
        ::CloseHandle(kProcessHandle);
        if (kOpenTokenOk == FALSE || tokenOut == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "OpenProcessToken failed: " + formatLastErrorMessage(kOpenTokenError);
            }
            return false;
        }
        return true;
    }

    // Optionally duplicate the source token into a Primary Token (commonly used by CreateProcessAsUserW).
    bool duplicatePrimaryTokenHandle(
        const HANDLE sourceToken,
        const DWORD desiredAccess,
        HANDLE& duplicatedTokenOut,
        std::string* const errorMessage)
    {
        duplicatedTokenOut = nullptr;
        const BOOL kDuplicateOk = ::DuplicateTokenEx(
            sourceToken,
            desiredAccess,
            nullptr,
            SecurityImpersonation,
            TokenPrimary,
            &duplicatedTokenOut);
        if (kDuplicateOk == FALSE || duplicatedTokenOut == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "DuplicateTokenEx(TokenPrimary) failed: " + formatLastErrorMessage(::GetLastError());
            }
            return false;
        }
        return true;
    }

    // Adjust a single privilege using AdjustTokenPrivileges.
    bool applySinglePrivilegeEdit(
        const HANDLE tokenHandle,
        const ks::process::TokenPrivilegeEdit& privilegeEdit,
        std::string* const errorMessage)
    {
        if (privilegeEdit.action == ks::process::TokenPrivilegeAction::kKeep)
        {
            return true;
        }

        const std::string kPrivilegeNameUtf8 = ks::str::trimCopy(privilegeEdit.privilegeName);
        if (kPrivilegeNameUtf8.empty())
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "Privilege name is empty.";
            }
            return false;
        }

        const std::wstring kPrivilegeNameWide = ks::str::utf8ToUtf16(kPrivilegeNameUtf8);
        if (kPrivilegeNameWide.empty())
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "Privilege name UTF-8 -> UTF-16 conversion failed: " + kPrivilegeNameUtf8;
            }
            return false;
        }

        LUID privilegeLuid{};
        if (::LookupPrivilegeValueW(nullptr, kPrivilegeNameWide.c_str(), &privilegeLuid) == FALSE)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "LookupPrivilegeValue failed(" + kPrivilegeNameUtf8 + "): " + formatLastErrorMessage(::GetLastError());
            }
            return false;
        }

        TOKEN_PRIVILEGES tokenPrivileges{};
        tokenPrivileges.PrivilegeCount = 1;
        tokenPrivileges.Privileges[0].Luid = privilegeLuid;
        switch (privilegeEdit.action)
        {
        case ks::process::TokenPrivilegeAction::kEnable:
            tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            break;
        case ks::process::TokenPrivilegeAction::kDisable:
            tokenPrivileges.Privileges[0].Attributes = 0;
            break;
        case ks::process::TokenPrivilegeAction::kRemove:
            tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_REMOVED;
            break;
        case ks::process::TokenPrivilegeAction::kKeep:
        default:
            tokenPrivileges.Privileges[0].Attributes = 0;
            break;
        }

        ::SetLastError(ERROR_SUCCESS);
        if (::AdjustTokenPrivileges(
            tokenHandle,
            FALSE,
            &tokenPrivileges,
            static_cast<DWORD>(sizeof(tokenPrivileges)),
            nullptr,
            nullptr) == FALSE)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "AdjustTokenPrivileges failed(" + kPrivilegeNameUtf8 + "): " + formatLastErrorMessage(::GetLastError());
            }
            return false;
        }

        const DWORD kAdjustError = ::GetLastError();
        if (kAdjustError != ERROR_SUCCESS)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "AdjustTokenPrivileges returned error(" + kPrivilegeNameUtf8 + "): " + formatLastErrorMessage(kAdjustError);
            }
            return false;
        }
        return true;
    }

    // Batch apply privilege edits.
    bool applyPrivilegeEdits(
        const HANDLE tokenHandle,
        const std::vector<ks::process::TokenPrivilegeEdit>& edits,
        std::string* const errorMessage)
    {
        for (std::size_t editIndex = 0; editIndex < edits.size(); ++editIndex)
        {
            if (!applySinglePrivilegeEdit(tokenHandle, edits[editIndex], errorMessage))
            {
                if (errorMessage != nullptr)
                {
                    *errorMessage = "PrivilegeEdit[" + std::to_string(editIndex) + "] failed: " + *errorMessage;
                }
                return false;
            }
        }
        return true;
    }

    // DeferredRemoteLoadLibraryCleanup:
    // - Input: Saves the still-executing remote LoadLibraryW thread, target process handle, and remote DLL path address;
    // - Processing: Defer freeing the remote address until after the remote thread has definitely finished to avoid remote Use-After-Free on timeout return.
    // - Returns: the sole context for the background cleanup thread, released by the cleanup thread.
    // - Reason: LoadLibraryW timeout does not imply the remote thread has stopped; the caller cannot synchronously free its argument memory.
    struct DeferredRemoteLoadLibraryCleanup
    {
        HANDLE processHandle = nullptr;
        HANDLE remoteThread = nullptr;
        void* remotePathMemory = nullptr;
    };

    // completeDeferredRemoteLoadLibraryCleanup:
    // - Input: parameterValue points to a DeferredRemoteLoadLibraryCleanup object after ownership transfer;
    // - Processing: Wait for the remote LoadLibraryW thread to terminate, then release the remote path memory it read and all associated handles.
    // - Return: Always returns 0; background cleanup failure does not affect the calling thread's already returned injection diagnostics.
    DWORD WINAPI completeDeferredRemoteLoadLibraryCleanup(const LPVOID parameterValue)
    {
        auto* const kCleanupContext = static_cast<DeferredRemoteLoadLibraryCleanup*>(parameterValue);
        if (kCleanupContext == nullptr)
        {
            return 0;
        }

        const DWORD kWaitResult = ::WaitForSingleObject(kCleanupContext->remoteThread, INFINITE);
        if (kWaitResult == WAIT_OBJECT_0)
        {
            (void)::VirtualFreeEx(kCleanupContext->processHandle, kCleanupContext->remotePathMemory, 0, MEM_RELEASE);
        }

        if (kCleanupContext->remoteThread != nullptr)
        {
            ::CloseHandle(kCleanupContext->remoteThread);
        }
        if (kCleanupContext->processHandle != nullptr)
        {
            ::CloseHandle(kCleanupContext->processHandle);
        }
        delete kCleanupContext;
        return 0;
    }

    // scheduleDeferredRemoteLoadLibraryCleanup:
    // - Input: An incomplete remote LoadLibraryW thread and its still-accessed parameter memory.
    // Processing: Create an independent background thread to take over all resources, preventing erroneous release of remote parameters after the main thread times out.
    // - Returns: true if resource ownership is successfully transferred; on failure, the caller must retain the remote memory.
    bool scheduleDeferredRemoteLoadLibraryCleanup(
        const HANDLE processHandle,
        const HANDLE remoteThread,
        void* const remotePathMemory)
    {
        auto* const kCleanupContext = new (std::nothrow) DeferredRemoteLoadLibraryCleanup{
            processHandle,
            remoteThread,
            remotePathMemory
        };
        if (kCleanupContext == nullptr)
        {
            return false;
        }

        HANDLE cleanupThread = ::CreateThread(
            nullptr,
            0,
            &completeDeferredRemoteLoadLibraryCleanup,
            kCleanupContext,
            0,
            nullptr);
        if (cleanupThread == nullptr)
        {
            delete kCleanupContext;
            return false;
        }

        ::CloseHandle(cleanupThread);
        return true;
    }
}

namespace ks::process
{
    const std::vector<std::string>& knownTokenPrivilegeNames()
    {
        // Complete directory of SE_*_NAME from Windows SDK winnt.h, maintaining the order defined in the SDK.
        static const std::vector<std::string> kPrivilegeNames{
            ks::str::utf16ToUtf8(SE_CREATE_TOKEN_NAME),
            ks::str::utf16ToUtf8(SE_ASSIGNPRIMARYTOKEN_NAME),
            ks::str::utf16ToUtf8(SE_LOCK_MEMORY_NAME),
            ks::str::utf16ToUtf8(SE_INCREASE_QUOTA_NAME),
            ks::str::utf16ToUtf8(SE_UNSOLICITED_INPUT_NAME),
            ks::str::utf16ToUtf8(SE_MACHINE_ACCOUNT_NAME),
            ks::str::utf16ToUtf8(SE_TCB_NAME),
            ks::str::utf16ToUtf8(SE_SECURITY_NAME),
            ks::str::utf16ToUtf8(SE_TAKE_OWNERSHIP_NAME),
            ks::str::utf16ToUtf8(SE_LOAD_DRIVER_NAME),
            ks::str::utf16ToUtf8(SE_SYSTEM_PROFILE_NAME),
            ks::str::utf16ToUtf8(SE_SYSTEMTIME_NAME),
            ks::str::utf16ToUtf8(SE_PROF_SINGLE_PROCESS_NAME),
            ks::str::utf16ToUtf8(SE_INC_BASE_PRIORITY_NAME),
            ks::str::utf16ToUtf8(SE_CREATE_PAGEFILE_NAME),
            ks::str::utf16ToUtf8(SE_CREATE_PERMANENT_NAME),
            ks::str::utf16ToUtf8(SE_BACKUP_NAME),
            ks::str::utf16ToUtf8(SE_RESTORE_NAME),
            ks::str::utf16ToUtf8(SE_SHUTDOWN_NAME),
            ks::str::utf16ToUtf8(SE_DEBUG_NAME),
            ks::str::utf16ToUtf8(SE_AUDIT_NAME),
            ks::str::utf16ToUtf8(SE_SYSTEM_ENVIRONMENT_NAME),
            ks::str::utf16ToUtf8(SE_CHANGE_NOTIFY_NAME),
            ks::str::utf16ToUtf8(SE_REMOTE_SHUTDOWN_NAME),
            ks::str::utf16ToUtf8(SE_UNDOCK_NAME),
            ks::str::utf16ToUtf8(SE_SYNC_AGENT_NAME),
            ks::str::utf16ToUtf8(SE_ENABLE_DELEGATION_NAME),
            ks::str::utf16ToUtf8(SE_MANAGE_VOLUME_NAME),
            ks::str::utf16ToUtf8(SE_IMPERSONATE_NAME),
            ks::str::utf16ToUtf8(SE_CREATE_GLOBAL_NAME),
            ks::str::utf16ToUtf8(SE_TRUSTED_CREDMAN_ACCESS_NAME),
            ks::str::utf16ToUtf8(SE_RELABEL_NAME),
            ks::str::utf16ToUtf8(SE_INC_WORKING_SET_NAME),
            ks::str::utf16ToUtf8(SE_TIME_ZONE_NAME),
            ks::str::utf16ToUtf8(SE_CREATE_SYMBOLIC_LINK_NAME),
            ks::str::utf16ToUtf8(SE_DELEGATE_SESSION_USER_IMPERSONATE_NAME)
        };
        return kPrivilegeNames;
    }

    std::string buildProcessIdentityKey(const std::uint32_t pid, const std::uint64_t creationTime100ns)
    {
        // identity rule: PID#CreationTime100ns.
        return std::to_string(pid) + "#" + std::to_string(creationTime100ns);
    }

    std::string buildThreadIdentityKey(
        const std::uint32_t pid,
        const std::uint32_t threadId,
        const std::uint64_t creationTime100ns)
    {
        // If creation time is unavailable, retain PID/TID; if reuse occurs, the cumulative counter rollback will re-establish the baseline for this round.
        return std::to_string(pid) + "#" + std::to_string(threadId) + "#" +
            std::to_string(creationTime100ns);
    }

    bool queryProcessCreationTimeByPid(
        const std::uint32_t pid,
        std::uint64_t* const creationTime100nsOut,
        std::string* const detailTextOut)
    {
        // creationTime100nsOut: Caller must provide a valid output address; on failure, it remains 0.
        if (creationTime100nsOut == nullptr)
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = "process creation time output is null";
            }
            return false;
        }
        *creationTime100nsOut = 0U;

        // processHandle: Request only the limited query permissions required for identity verification, without expanding the target process access surface.
        const HANDLE kProcessHandle = ::OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION,
            FALSE,
            toDwordPid(pid));
        if (kProcessHandle == nullptr)
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = "OpenProcess failed(" + std::to_string(::GetLastError()) + ")";
            }
            return false;
        }

        // The four FILETIME outputs are populated in a single call to GetProcessTimes; here, only creationTime is consumed.
        FILETIME creationTime{};
        FILETIME exitTime{};
        FILETIME kernelTime{};
        FILETIME userTime{};
        const BOOL kQueryResult = ::GetProcessTimes(
            kProcessHandle,
            &creationTime,
            &exitTime,
            &kernelTime,
            &userTime);

        // queryError: Must be saved before closing the handle to prevent CloseHandle from overwriting the thread's error code.
        const DWORD kQueryError = kQueryResult != FALSE ? ERROR_SUCCESS : ::GetLastError();
        ::CloseHandle(kProcessHandle);
        if (kQueryResult == FALSE)
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = "GetProcessTimes failed(" + std::to_string(kQueryError) + ")";
            }
            return false;
        }

        // creationTimeValue: Convert FILETIME high/low parts to the project's unified 100ns identity value.
        const std::uint64_t kCreationTimeValue = ks::str::fileTimeToUint64(
            creationTime.dwHighDateTime,
            creationTime.dwLowDateTime);
        if (kCreationTimeValue == 0U)
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = "process creation time is zero";
            }
            return false;
        }

        *creationTime100nsOut = kCreationTimeValue;
        if (detailTextOut != nullptr)
        {
            detailTextOut->clear();
        }
        return true;
    }

    bool refreshProcessDynamicCounters(ProcessRecord& processRecord)
    {
        // For system-reserved processes such as PID 0/4, many API calls may fail to open a handle.
        if (processRecord.pid == 0)
        {
            processRecord.dynamicCountersReady = false;
            processRecord.ramMB = 0.0;
            processRecord.diskMBps = 0.0;
            processRecord.cpuPercent = 0.0;
            processRecord.gpuPercent = 0.0;
            processRecord.netKBps = 0.0;
            processRecord.netRxKBps = 0.0;
            processRecord.netTxKBps = 0.0;
            return false;
        }

        const HANDLE kProcessHandle = ::OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
            FALSE,
            toDwordPid(processRecord.pid));
        if (kProcessHandle == nullptr)
        {
            // Fallback path:
            // - Some protected processes reject PROCESS_VM_READ but may still allow limited queries;
            // - The "Handle Count" in the Resource View depends solely on PROCESS_QUERY_LIMITED_INFORMATION; attempt it once independently.
            const HANDLE kLimitedProcessHandle = ::OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION,
                FALSE,
                toDwordPid(processRecord.pid));
            if (kLimitedProcessHandle != nullptr)
            {
                DWORD processHandleCount = 0;
                if (::GetProcessHandleCount(kLimitedProcessHandle, &processHandleCount) != FALSE)
                {
                    processRecord.handleCount = static_cast<std::uint32_t>(processHandleCount);
                }
                ::CloseHandle(kLimitedProcessHandle);
            }
            processRecord.dynamicCountersReady = false;
            return false;
        }

        // Read creation time + cumulative CPU time.
        FILETIME creationTime{};
        FILETIME exitTime{};
        FILETIME kernelTime{};
        FILETIME userTime{};
        if (::GetProcessTimes(kProcessHandle, &creationTime, &exitTime, &kernelTime, &userTime) != FALSE)
        {
            processRecord.creationTime100ns = ks::str::fileTimeToUint64(
                creationTime.dwHighDateTime,
                creationTime.dwLowDateTime);
            processRecord.rawCpuTime100ns =
                ks::str::fileTimeToUint64(kernelTime.dwHighDateTime, kernelTime.dwLowDateTime) +
                ks::str::fileTimeToUint64(userTime.dwHighDateTime, userTime.dwLowDateTime);
            processRecord.startTimeText = ks::str::fileTime100nsToLocalText(processRecord.creationTime100ns);
        }

        // Read RAM working set.
        PROCESS_MEMORY_COUNTERS_EX memoryCounters{};
        if (::GetProcessMemoryInfo(
            kProcessHandle,
            reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&memoryCounters),
            sizeof(memoryCounters)) != FALSE)
        {
            processRecord.rawWorkingSetBytes = static_cast<std::uint64_t>(memoryCounters.WorkingSetSize);
            processRecord.rawPrivateBytes = static_cast<std::uint64_t>(memoryCounters.PrivateUsage);
            if (processRecord.rawPrivateBytes == 0)
            {
                processRecord.rawPrivateBytes = static_cast<std::uint64_t>(memoryCounters.PagefileUsage);
            }
            processRecord.workingSetMB = static_cast<double>(processRecord.rawWorkingSetBytes) / (1024.0 * 1024.0);
            processRecord.ramMB = static_cast<double>(processRecord.rawPrivateBytes) / (1024.0 * 1024.0);

            // Task Manager memory column alignment:
            // - Toolhelp and other non-NtQuery paths lack SYSTEM_PROCESS_INFORMATION; Psapi must be used to fill the gap.
            // - Private/shared working set is not in PROCESS_MEMORY_COUNTERS_EX; keep privateWorkingSetKnown=false
            //   so the UI displays a placeholder instead of mislabeling 'Commit Size' as 'Private Working Set'.
            processRecord.peakWorkingSetBytes = static_cast<std::uint64_t>(memoryCounters.PeakWorkingSetSize);
            processRecord.commitSizeBytes = static_cast<std::uint64_t>(memoryCounters.PagefileUsage);
            processRecord.peakCommitSizeBytes = static_cast<std::uint64_t>(memoryCounters.PeakPagefileUsage);
            processRecord.pagedPoolBytes = static_cast<std::uint64_t>(memoryCounters.QuotaPagedPoolUsage);
            processRecord.nonPagedPoolBytes = static_cast<std::uint64_t>(memoryCounters.QuotaNonPagedPoolUsage);
            processRecord.pageFaultCount = static_cast<std::uint64_t>(memoryCounters.PageFaultCount);
            processRecord.memoryDetailKnown = true;
        }

        // Read cumulative IO bytes.
        IO_COUNTERS ioCounters{};
        if (::GetProcessIoCounters(kProcessHandle, &ioCounters) != FALSE)
        {
            processRecord.rawIoBytes =
                static_cast<std::uint64_t>(ioCounters.ReadTransferCount) +
                static_cast<std::uint64_t>(ioCounters.WriteTransferCount) +
                static_cast<std::uint64_t>(ioCounters.OtherTransferCount);

            // The 6 I/O columns in Task Manager come directly from the same query, incurring no additional overhead.
            processRecord.ioReadOperationCount = static_cast<std::uint64_t>(ioCounters.ReadOperationCount);
            processRecord.ioWriteOperationCount = static_cast<std::uint64_t>(ioCounters.WriteOperationCount);
            processRecord.ioOtherOperationCount = static_cast<std::uint64_t>(ioCounters.OtherOperationCount);
            processRecord.ioReadTransferBytes = static_cast<std::uint64_t>(ioCounters.ReadTransferCount);
            processRecord.ioWriteTransferBytes = static_cast<std::uint64_t>(ioCounters.WriteTransferCount);
            processRecord.ioOtherTransferBytes = static_cast<std::uint64_t>(ioCounters.OtherTransferCount);
            processRecord.ioDetailKnown = true;
        }

        // Base priority and cumulative cycle time:
        // - Base priority is taken from KPRIORITY (0~31), consistent with the semantics of the "Base Priority" column in Task Manager.
        // - QueryProcessCycleTime is available on Windows 7+; on failure, cycleTimeKnown remains false.
        applyProcessBasePriorityAndCycleTimeByHandle(processRecord, kProcessHandle);

        // If the path is not set, attempt to retrieve it as well.
        if (processRecord.imagePath.empty())
        {
            processRecord.imagePath = queryProcessPathByHandle(kProcessHandle);
        }

        // During the dynamic refresh phase, priority and architecture text are updated concurrently to enable real-time display in the details window.
        processRecord.priorityText = queryPriorityTextByHandle(kProcessHandle);
        processRecord.efficiencyModeSupported = queryProcessEfficiencyModeByHandle(
            kProcessHandle,
            &processRecord.efficiencyModeEnabled,
            nullptr);
        if (processRecord.architectureText.empty() || processRecord.architectureText == "Unknown")
        {
            processRecord.architectureText = queryProcessArchitectureByHandle(kProcessHandle);
        }

        // The handle count is a dynamic column in the resource view and must be read before closing the processHandle.
        DWORD processHandleCount = 0;
        if (::GetProcessHandleCount(kProcessHandle, &processHandleCount) != FALSE)
        {
            processRecord.handleCount = static_cast<std::uint32_t>(processHandleCount);
        }
        ::CloseHandle(kProcessHandle);

        // GPU metrics are aggregated uniformly during the process list enumeration phase via PDH GPU Engine to avoid redundant sampling when opening handles for individual processes.
        // Network rate requires cross-process page capture window calculation; single-process dynamic refresh cannot yield reliable cumulative values, so set to 0.
        processRecord.netKBps = 0.0;
        processRecord.netRxKBps = 0.0;
        processRecord.netTxKBps = 0.0;
        processRecord.dynamicCountersReady = true;
        return true;
    }

    bool queryProcessProtectionLevelByPid(
        const std::uint32_t pid,
        std::uint32_t* const levelOut,
        std::string* const displayTextOut,
        std::string* const errorMessageOut)
    {
        // Output parameters are zeroed first to ensure no stale values from the previous run remain on the failure path.
        if (levelOut != nullptr)
        {
            *levelOut = 0;
        }
        if (displayTextOut != nullptr)
        {
            displayTextOut->clear();
        }
        if (errorMessageOut != nullptr)
        {
            errorMessageOut->clear();
        }

        // PID 0 has no regular process handle; directly return None from the public enumeration.
        if (pid == 0)
        {
            if (levelOut != nullptr)
            {
                *levelOut = kProcessProtectionLevelNone;
            }
            if (displayTextOut != nullptr)
            {
                *displayTextOut = processProtectionLevelToText(kProcessProtectionLevelNone);
            }
            return true;
        }

        // GetProcessInformation is dynamically resolved from kernel32 to support older SDKs and runtime environments.
        HMODULE kernel32Module = ::GetModuleHandleW(L"kernel32.dll");
        const auto kGetProcessInformation = reinterpret_cast<GetProcessInformationFn>(
            kernel32Module != nullptr ? ::GetProcAddress(kernel32Module, "GetProcessInformation") : nullptr);
        if (kGetProcessInformation == nullptr)
        {
            if (errorMessageOut != nullptr)
            {
                *errorMessageOut = "GetProcessInformation(ProcessProtectionLevelInfo) is not available.";
            }
            return false;
        }

        // Querying PPL enumeration only requires limited query permissions, avoiding unnecessary VM_READ requests.
        const HANDLE kProcessHandle = ::OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION,
            FALSE,
            toDwordPid(pid));
        if (kProcessHandle == nullptr)
        {
            if (errorMessageOut != nullptr)
            {
                *errorMessageOut = "OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION) failed: "
                    + formatLastErrorMessage(::GetLastError());
            }
            return false;
        }

        ProcessProtectionLevelInformationNative protectionInfo{};
        const BOOL kQueryOk = kGetProcessInformation(
            kProcessHandle,
            kProcessProtectionLevelInfoClass,
            &protectionInfo,
            static_cast<DWORD>(sizeof(protectionInfo)));
        const DWORD kQueryError = ::GetLastError();
        ::CloseHandle(kProcessHandle);

        if (kQueryOk == FALSE)
        {
            if (errorMessageOut != nullptr)
            {
                *errorMessageOut = "GetProcessInformation(ProcessProtectionLevelInfo) failed: "
                    + formatLastErrorMessage(kQueryError);
            }
            return false;
        }

        if (levelOut != nullptr)
        {
            *levelOut = static_cast<std::uint32_t>(protectionInfo.protectionLevel);
        }
        if (displayTextOut != nullptr)
        {
            *displayTextOut = processProtectionLevelToText(protectionInfo.protectionLevel);
        }
        return true;
    }

    bool fillProcessStaticDetails(ProcessRecord& processRecord, const bool includeSignatureCheck)
    {
        // Static details phase requires elevated permissions to read command-line and token information.
        if (processRecord.pid == 0)
        {
            // PID 0 (Idle) has no regular user-mode image; signature logic does not apply.
            processRecord.signatureState = includeSignatureCheck ? "Unsigned" : "Pending";
            processRecord.signaturePublisher = "System";
            processRecord.signatureTrusted = false;
            processRecord.architectureText = "N/A";
            processRecord.priorityText = "Idle";
            processRecord.staticDetailsReady = true;
            return true;
        }

        // First attempt a VM_READ handle (to read the command line); fall back to a limited handle on failure.
        HANDLE processHandle = ::OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
            FALSE,
            toDwordPid(processRecord.pid));
        if (processHandle == nullptr)
        {
            processHandle = ::OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION,
                FALSE,
                toDwordPid(processRecord.pid));
        }
        if (processHandle == nullptr)
        {
            processRecord.staticDetailsReady = false;
            return false;
        }

        // Executable path.
        if (processRecord.imagePath.empty())
        {
            processRecord.imagePath = queryProcessPathByHandle(processHandle);
        }

        // Fallback for process name: extract filename from path.
        if (processRecord.processName.empty())
        {
            processRecord.processName = extractFileNameFromPath(processRecord.imagePath);
        }

        // Command line, user, and administrator status.
        processRecord.commandLine = queryProcessCommandLineByHandle(processHandle);
        processRecord.userName = queryProcessUserNameByHandle(processHandle);
        processRecord.isAdmin = queryProcessIsElevatedByHandle(processHandle);
        processRecord.architectureText = queryProcessArchitectureByHandle(processHandle);
        processRecord.priorityText = queryPriorityTextByHandle(processHandle);
        processRecord.efficiencyModeSupported = queryProcessEfficiencyModeByHandle(
            processHandle,
            &processRecord.efficiencyModeEnabled,
            nullptr);
        if (processRecord.sessionId == 0)
        {
            DWORD sessionId = 0;
            if (::ProcessIdToSessionId(toDwordPid(processRecord.pid), &sessionId) != FALSE)
            {
                processRecord.sessionId = static_cast<std::uint32_t>(sessionId);
            }
        }

        // If the creation time is not set, attempt to fill it in.
        if (processRecord.creationTime100ns == 0)
        {
            FILETIME creationTime{};
            FILETIME exitTime{};
            FILETIME kernelTime{};
            FILETIME userTime{};
            if (::GetProcessTimes(processHandle, &creationTime, &exitTime, &kernelTime, &userTime) != FALSE)
            {
                processRecord.creationTime100ns = ks::str::fileTimeToUint64(
                    creationTime.dwHighDateTime,
                    creationTime.dwLowDateTime);
            }
        }

        if (!processRecord.startTimeText.empty() || processRecord.creationTime100ns == 0)
        {
            // No need to reformat.
        }
        else
        {
            processRecord.startTimeText = ks::str::fileTime100nsToLocalText(processRecord.creationTime100ns);
        }

        ::CloseHandle(processHandle);

        // Digital signature verification is typically relatively time-consuming:
        // - Detailed mode: Performs actual signature verification;
        // - Fast mode: mark as Pending only; detailed mode will fill in the rest later.
        if (includeSignatureCheck)
        {
            const FileSignatureInfo kSignatureInfo = queryFileSignatureInfo(processRecord.imagePath);
            processRecord.signatureState = kSignatureInfo.displayText.empty() ? "Unknown" : kSignatureInfo.displayText;
            processRecord.signaturePublisher = kSignatureInfo.publisher;
            processRecord.signatureTrusted = kSignatureInfo.trustedByWindows;
        }
        else if (processRecord.signatureState.empty())
        {
            processRecord.signatureState = "Pending";
            processRecord.signaturePublisher.clear();
            processRecord.signatureTrusted = false;
        }

        // Clean invisible characters to prevent table display anomalies.
        ks::str::replaceAllInPlace(processRecord.commandLine, "\r", " ");
        ks::str::replaceAllInPlace(processRecord.commandLine, "\n", " ");
        processRecord.commandLine = ks::str::trimCopy(processRecord.commandLine);
        processRecord.userName = ks::str::trimCopy(processRecord.userName);
        processRecord.signaturePublisher = ks::str::trimCopy(processRecord.signaturePublisher);

        // staticDetailsReady here indicates that basic static fields are available; even if the signature
        // is Pending, it is displayable, and the signature can be supplemented later as needed.
        processRecord.staticDetailsReady = true;
        return true;
    }

    bool fillProcessOnDemandDetails(
        ProcessRecord& processRecord,
        const std::uint32_t detailDemandFlags,
        std::uint32_t* const resolvedFlagsOut)
    {
        // resolvedFlags: The bits that were successfully collected in this run, used by the caller for 'collect once' accounting.
        std::uint32_t resolvedFlags = process_detail_demand::kNone;
        const auto kPublishResolvedFlags = [resolvedFlagsOut, &resolvedFlags]() -> void
            {
                if (resolvedFlagsOut != nullptr)
                {
                    *resolvedFlagsOut = resolvedFlags;
                }
            };

        if (detailDemandFlags == process_detail_demand::kNone)
        {
            kPublishResolvedFlags();
            return true;
        }

        bool anySucceeded = false;

        // First group: relies solely on the image file on disk, allowing cross-process sharing of parsed results by path.
        const bool kWantFileDescription =
            (detailDemandFlags & process_detail_demand::kFileDescription) != 0U;
        const bool kWantOsContext =
            (detailDemandFlags & process_detail_demand::kOsContext) != 0U;
        if ((kWantFileDescription || kWantOsContext) && !processRecord.imagePath.empty())
        {
            std::string fileDescription;
            std::string osContextText;
            resolveImageDescriptionCached(
                processRecord.imagePath,
                kWantFileDescription,
                kWantOsContext,
                &fileDescription,
                &osContextText);
            if (kWantFileDescription)
            {
                processRecord.fileDescription = std::move(fileDescription);
            }
            if (kWantOsContext)
            {
                processRecord.osContextText = std::move(osContextText);
            }
            resolvedFlags |= (detailDemandFlags & process_detail_demand::kImageFileMask);
            anySucceeded = true;
        }

        // Enterprise context:
        // - Windows Information Protection (WIP/EDP) has no public API to query 'arbitrary process enterprise context';
        // - On systems where WIP is not enabled, Task Manager also displays 'Personal'; maintain the same semantics here without inference.
        // - Values use stable English identifiers; the UI layer translates them for display based on the current language.
        if ((detailDemandFlags & process_detail_demand::kEnterpriseContext) != 0U)
        {
            processRecord.enterpriseContextText = "Personal";
            resolvedFlags |= process_detail_demand::kEnterpriseContext;
            anySucceeded = true;
        }

        // Group 2: Requires the target process handle. If no bits are requested, skip OpenProcess directly.
        constexpr std::uint32_t kHandleRequiredMask =
            process_detail_demand::kGuiResources |
            process_detail_demand::kJobObject |
            process_detail_demand::kMitigationPolicy |
            process_detail_demand::kUacVirtualization |
            process_detail_demand::kPackageName |
            process_detail_demand::kDpiAwareness;
        if ((detailDemandFlags & kHandleRequiredMask) == 0U || processRecord.pid == 0)
        {
            kPublishResolvedFlags();
            return anySucceeded;
        }

        // GetGuiResources and GetProcessMitigationPolicy require PROCESS_QUERY_INFORMATION;
        // Protected processes only allow the LIMITED version; retry with downgrade to retrieve whatever is available.
        HANDLE processHandle = ::OpenProcess(
            PROCESS_QUERY_INFORMATION,
            FALSE,
            toDwordPid(processRecord.pid));
        if (processHandle == nullptr)
        {
            processHandle = ::OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION,
                FALSE,
                toDwordPid(processRecord.pid));
        }
        if (processHandle == nullptr)
        {
            kPublishResolvedFlags();
            return anySucceeded;
        }

        if ((detailDemandFlags & process_detail_demand::kGuiResources) != 0U)
        {
            // GetGuiResources returns 0 and sets LastError on failure; use LastError to distinguish 'truly 0 objects'.
            ::SetLastError(ERROR_SUCCESS);
            const DWORD kGdiObjectCount = ::GetGuiResources(processHandle, GR_GDIOBJECTS);
            const DWORD kGdiQueryError = ::GetLastError();
            ::SetLastError(ERROR_SUCCESS);
            const DWORD kUserObjectCount = ::GetGuiResources(processHandle, GR_USEROBJECTS);
            const DWORD kUserQueryError = ::GetLastError();
            if (kGdiQueryError == ERROR_SUCCESS || kUserQueryError == ERROR_SUCCESS)
            {
                processRecord.gdiObjectCount = static_cast<std::uint32_t>(kGdiObjectCount);
                processRecord.userObjectCount = static_cast<std::uint32_t>(kUserObjectCount);
                processRecord.guiResourceKnown = true;
                resolvedFlags |= process_detail_demand::kGuiResources;
                anySucceeded = true;
            }
        }

        if ((detailDemandFlags & process_detail_demand::kJobObject) != 0U)
        {
            BOOL inJobObject = FALSE;
            if (::IsProcessInJob(processHandle, nullptr, &inJobObject) != FALSE)
            {
                processRecord.inJobObject = (inJobObject != FALSE);
                processRecord.jobObjectKnown = true;
                resolvedFlags |= process_detail_demand::kJobObject;
                anySucceeded = true;
            }
        }

        if ((detailDemandFlags & process_detail_demand::kMitigationPolicy) != 0U)
        {
            if (applyProcessMitigationStatesByHandle(processRecord, processHandle))
            {
                resolvedFlags |= process_detail_demand::kMitigationPolicy;
                anySucceeded = true;
            }
        }

        if ((detailDemandFlags & process_detail_demand::kUacVirtualization) != 0U)
        {
            const ProcessFeatureState kVirtualizationState =
                queryProcessUacVirtualizationStateByHandle(processHandle);
            processRecord.uacVirtualizationState = kVirtualizationState;
            if (kVirtualizationState != ProcessFeatureState::kUnknown)
            {
                resolvedFlags |= process_detail_demand::kUacVirtualization;
                anySucceeded = true;
            }
        }

        if ((detailDemandFlags & process_detail_demand::kPackageName) != 0U)
        {
            std::string packageFullName;
            if (queryProcessPackageFullName(processHandle, &packageFullName))
            {
                processRecord.packageFullName = std::move(packageFullName);
                processRecord.packageNameKnown = true;
                resolvedFlags |= process_detail_demand::kPackageName;
                anySucceeded = true;
            }
        }

        if ((detailDemandFlags & process_detail_demand::kDpiAwareness) != 0U)
        {
            const ProcessDpiAwarenessLevel kAwarenessLevel = queryProcessDpiAwarenessLevel(processHandle);
            processRecord.dpiAwarenessLevel = kAwarenessLevel;
            if (kAwarenessLevel != ProcessDpiAwarenessLevel::kUnknown)
            {
                resolvedFlags |= process_detail_demand::kDpiAwareness;
                anySucceeded = true;
            }
        }

        ::CloseHandle(processHandle);
        kPublishResolvedFlags();
        return anySucceeded;
    }

    void clearProcessImageDescriptionCache()
    {
        std::lock_guard<std::mutex> cacheLock(imageDescriptionCacheMutex());
        imageDescriptionCache().clear();
    }

    void updateDerivedCounters(
        ProcessRecord& processRecord,
        const CounterSample* previousSample,
        CounterSample& nextSampleOut,
        const std::uint32_t logicalCpuCount,
        const std::uint64_t currentTick100ns)
    {
        // Write the next sample first to ensure the caller can update the baseline regardless of success or failure.
        nextSampleOut.cpuTime100ns = processRecord.rawCpuTime100ns;
        nextSampleOut.ioBytes = processRecord.rawIoBytes;
        nextSampleOut.sampleTick100ns = currentTick100ns;
        nextSampleOut.workingSetBytes = processRecord.rawWorkingSetBytes;
        nextSampleOut.pageFaultCount = processRecord.pageFaultCount;
        nextSampleOut.hasMemoryBaseline = processRecord.memoryDetailKnown;

        // RAM retains both allocated memory and working set to facilitate UI display of 'allocated' and 'used' values.
        processRecord.workingSetMB = static_cast<double>(processRecord.rawWorkingSetBytes) / (1024.0 * 1024.0);
        processRecord.ramMB = static_cast<double>(processRecord.rawPrivateBytes) / (1024.0 * 1024.0);

        // Shared working set is a derived value: it is only meaningful when the private working set is available; otherwise, it remains 0 and the UI displays a placeholder.
        processRecord.sharedWorkingSetBytes =
            (processRecord.privateWorkingSetKnown &&
                processRecord.rawWorkingSetBytes > processRecord.privateWorkingSetBytes)
            ? (processRecord.rawWorkingSetBytes - processRecord.privateWorkingSetBytes)
            : 0ULL;

        // Active private working set:
        // - Semantically, this represents the active portion within the private working set; for suspended/frozen processes, the entire working set is inactive.
        // - Therefore, suspended processes are recorded as 0, while others equal the private working set, consistent with Task Manager observations.
        processRecord.activePrivateWorkingSetBytes =
            (processRecord.processStateKnown && processRecord.processSuspended)
            ? 0ULL
            : processRecord.privateWorkingSetBytes;

        // Working set delta / page fault delta:
        // - These two columns in Task Manager represent the change between two consecutive refreshes and can be negative.
        // - Keep at 0 if there is no memory baseline in the first or previous round to avoid misinterpreting absolute values as deltas.
        if (previousSample != nullptr && previousSample->hasMemoryBaseline && processRecord.memoryDetailKnown)
        {
            processRecord.workingSetDeltaBytes =
                static_cast<std::int64_t>(processRecord.rawWorkingSetBytes) -
                static_cast<std::int64_t>(previousSample->workingSetBytes);
            processRecord.pageFaultDeltaCount =
                static_cast<std::int64_t>(processRecord.pageFaultCount) -
                static_cast<std::int64_t>(previousSample->pageFaultCount);
        }
        else
        {
            processRecord.workingSetDeltaBytes = 0;
            processRecord.pageFaultDeltaCount = 0;
        }

        // Without a previous sample, CPU/Disk cannot calculate deltas; GPU retains the value written during the PDH enumeration phase.
        if (previousSample == nullptr)
        {
            processRecord.cpuPercent = 0.0;
            processRecord.cpuCorePercent = 0.0;
            processRecord.diskMBps = 0.0;
            processRecord.netKBps = 0.0;
            processRecord.netRxKBps = 0.0;
            processRecord.netTxKBps = 0.0;
            return;
        }

        // Avoid division by zero when the sampling interval is too small or the clock has rolled back; similarly, retain the current PDH value for GPU.
        if (currentTick100ns <= previousSample->sampleTick100ns)
        {
            processRecord.cpuPercent = 0.0;
            processRecord.cpuCorePercent = 0.0;
            processRecord.diskMBps = 0.0;
            processRecord.netKBps = 0.0;
            processRecord.netRxKBps = 0.0;
            processRecord.netTxKBps = 0.0;
            return;
        }

        const std::uint64_t kDeltaTick100ns = currentTick100ns - previousSample->sampleTick100ns;
        const std::uint64_t kDeltaCpu100ns =
            (processRecord.rawCpuTime100ns >= previousSample->cpuTime100ns)
            ? (processRecord.rawCpuTime100ns - previousSample->cpuTime100ns)
            : 0;
        const std::uint64_t kDeltaIoBytes =
            (processRecord.rawIoBytes >= previousSample->ioBytes)
            ? (processRecord.rawIoBytes - previousSample->ioBytes)
            : 0;

        // CPU percentage retains both semantics simultaneously:
        // - cpuPercent: normalized relative to all logical processors, range 0~100;
        // - cpuCorePercent represents single-core equivalent usage; 100% means one logical processor is fully utilized, so multi-threaded processes can exceed 100%.
        const CpuUsageWindowResult kCpuUsage = calculateCpuUsageWindow(
            processRecord.rawCpuTime100ns,
            previousSample->cpuTime100ns,
            currentTick100ns,
            previousSample->sampleTick100ns,
            logicalCpuCount,
            logicalCpuCount);
        processRecord.cpuPercent = kCpuUsage.systemPercent;
        processRecord.cpuCorePercent = kCpuUsage.coreEquivalentPercent;

        // Note: To prevent processes with a CPU increment smaller than the display precision but non-zero from appearing
        // constantly at 0, assign a minimum visible value of 0.01% whenever the CPU increment is indeed greater than 0.
        if (kDeltaCpu100ns > 0 && processRecord.cpuPercent < 0.01)
        {
            processRecord.cpuPercent = 0.01;
        }
        if (kDeltaCpu100ns > 0 && processRecord.cpuCorePercent < 0.01)
        {
            processRecord.cpuCorePercent = 0.01;
        }

        // Disk throughput conversion: deltaIoBytes / deltaSeconds -> MB/s.
        const double kDeltaSeconds = static_cast<double>(kDeltaTick100ns) / 10000000.0;
        if (kDeltaSeconds > 0.0)
        {
            processRecord.diskMBps = (static_cast<double>(kDeltaIoBytes) / kDeltaSeconds) / (1024.0 * 1024.0);
        }
        else
        {
            processRecord.diskMBps = 0.0;
        }

        // Net is written by ProcessDock based on packet capture cumulative values after this function returns; GPU is not zeroed here to avoid overwriting PDH sampling results.
        processRecord.netKBps = 0.0;
        processRecord.netRxKBps = 0.0;
        processRecord.netTxKBps = 0.0;
    }

    void updateThreadCpuUsage(
        SystemThreadRecord& threadRecord,
        const ThreadCounterSample* const previousSample,
        ThreadCounterSample& nextSampleOut,
        const std::uint32_t logicalCpuCount,
        const std::uint64_t currentTick100ns)
    {
        const std::uint64_t kCurrentCpuTime100ns =
            threadRecord.kernelTime100ns + threadRecord.userTime100ns;
        nextSampleOut.cpuTime100ns = kCurrentCpuTime100ns;
        nextSampleOut.sampleTick100ns = currentTick100ns;
        threadRecord.cpuPercent = 0.0;
        threadRecord.cpuUsageReady = false;

        if (previousSample == nullptr)
        {
            return;
        }

        const CpuUsageWindowResult kCpuUsage = calculateCpuUsageWindow(
            kCurrentCpuTime100ns,
            previousSample->cpuTime100ns,
            currentTick100ns,
            previousSample->sampleTick100ns,
            logicalCpuCount,
            1U);
        if (!kCpuUsage.valid)
        {
            return;
        }

        threadRecord.cpuPercent = kCpuUsage.coreEquivalentPercent;
        if (kCurrentCpuTime100ns > previousSample->cpuTime100ns && threadRecord.cpuPercent < 0.01)
        {
            threadRecord.cpuPercent = 0.01;
        }
        threadRecord.cpuUsageReady = true;
    }

    std::vector<ProcessRecord> enumerateProcesses(
        const ProcessEnumStrategy strategy,
        ProcessEnumStrategy* const actualStrategyOut,
        const std::uint32_t detailDemandFlags)
    {
        // applyHandleCountFallback:
        // - On the final pass, overwrite the handle count with a system handle snapshot.
        // - This ensures that even if the target process cannot be opened via OpenProcess due to PPL or permission restrictions, the handle count is still observable from R3.
        const auto kApplyHandleCountFallback =
            [](std::vector<ProcessRecord>& processList) -> void
            {
                if (processList.empty())
                {
                    return;
                }

                const std::unordered_map<std::uint32_t, std::uint32_t> kHandleCountByPid =
                    queryProcessHandleCountsBySystemSnapshot();
                if (kHandleCountByPid.empty())
                {
                    return;
                }

                for (ProcessRecord& processRecord : processList)
                {
                    const auto kHandleCountIt = kHandleCountByPid.find(processRecord.pid);
                    if (kHandleCountIt != kHandleCountByPid.end())
                    {
                        processRecord.handleCount = kHandleCountIt->second;
                    }
                }
            };

        // applyGpuUsageFallback:
        // - Use the Windows PDH GPU Engine counter to fill in per-process GPU utilization.
        // - The enumeration policy itself does not provide GPU fields, so they must be aggregated uniformly before returning the list.
        const auto kApplyGpuUsageFallback =
            [detailDemandFlags](std::vector<ProcessRecord>& processList) -> void
            {
                applyGpuUsageCountersToProcessList(processList, detailDemandFlags);
            };

        // Internal lambda: Toolhelp path.
        const auto kEnumerateBySnapshot = []() -> std::vector<ProcessRecord>
            {
                std::vector<ProcessRecord> processList;

                HANDLE snapshotHandle = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
                if (snapshotHandle == INVALID_HANDLE_VALUE)
                {
                    return processList;
                }

                PROCESSENTRY32W processEntry{};
                processEntry.dwSize = sizeof(processEntry);
                if (::Process32FirstW(snapshotHandle, &processEntry) == FALSE)
                {
                    ::CloseHandle(snapshotHandle);
                    return processList;
                }

                // Iterate through snapshots and supplement dynamic counters.
                do
                {
                    ProcessRecord processRecord{};
                    processRecord.pid = static_cast<std::uint32_t>(processEntry.th32ProcessID);
                    processRecord.parentPid = static_cast<std::uint32_t>(processEntry.th32ParentProcessID);
                    processRecord.threadCount = static_cast<std::uint32_t>(processEntry.cntThreads);
                    processRecord.processName = ks::str::utf16ToUtf8(processEntry.szExeFile);

                    DWORD sessionId = 0;
                    if (::ProcessIdToSessionId(toDwordPid(processRecord.pid), &sessionId) != FALSE)
                    {
                        processRecord.sessionId = static_cast<std::uint32_t>(sessionId);
                    }

                    // The snapshot itself does not provide CPU/RAM/IO data; additional queries are required.
                    refreshProcessDynamicCounters(processRecord);
                    processList.push_back(std::move(processRecord));
                } while (::Process32NextW(snapshotHandle, &processEntry) != FALSE);

                ::CloseHandle(snapshotHandle);
                return processList;
            };

        // Internal lambda: NtQuerySystemInformation path.
        const auto kEnumerateByNtQuery = []() -> std::vector<ProcessRecord>
            {
                std::vector<ProcessRecord> processList;

                const auto kNtQuerySystemInformation = reinterpret_cast<NtQuerySystemInformationFn>(
                    getNtdllProcAddress("NtQuerySystemInformation"));
                if (kNtQuerySystemInformation == nullptr)
                {
                    return processList;
                }

                // Dynamically expand the buffer based on the return code.
                ULONG bufferLength = 1 * 1024 * 1024;
                std::vector<BYTE> informationBuffer(bufferLength);
                NTSTATUS queryStatus = kNtQuerySystemInformation(
                    SystemProcessInformation,
                    informationBuffer.data(),
                    bufferLength,
                    &bufferLength);

                while (queryStatus == kStatusInfoLengthMismatch)
                {
                    bufferLength = (bufferLength * 3) / 2 + 64 * 1024;
                    informationBuffer.resize(bufferLength);
                    queryStatus = kNtQuerySystemInformation(
                        SystemProcessInformation,
                        informationBuffer.data(),
                        bufferLength,
                        &bufferLength);
                }

                if (!NT_SUCCESS(queryStatus))
                {
                    return processList;
                }

                // Traverse the linked structure using NextEntryOffset.
                BYTE* currentPointer = informationBuffer.data();
                while (currentPointer != nullptr)
                {
                    const auto* processInfo = reinterpret_cast<const SystemProcessInformationRecord*>(currentPointer);
                    ProcessRecord processRecord{};

                    processRecord.pid = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(processInfo->uniqueProcessId));
                    processRecord.parentPid = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(processInfo->inheritedFromUniqueProcessId));
                    processRecord.threadCount = static_cast<std::uint32_t>(processInfo->numberOfThreads);
                    processRecord.handleCount = static_cast<std::uint32_t>(processInfo->handleCount);
                    processRecord.sessionId = static_cast<std::uint32_t>(processInfo->sessionId);
                    processRecord.creationTime100ns = static_cast<std::uint64_t>(processInfo->createTime.QuadPart);
                    processRecord.rawCpuTime100ns = static_cast<std::uint64_t>(processInfo->kernelTime.QuadPart + processInfo->userTime.QuadPart);
                    processRecord.rawWorkingSetBytes = static_cast<std::uint64_t>(processInfo->workingSetSize);
                    processRecord.rawPrivateBytes = static_cast<std::uint64_t>(processInfo->privatePageCount);
                    processRecord.rawIoBytes =
                        static_cast<std::uint64_t>(processInfo->readTransferCount.QuadPart) +
                        static_cast<std::uint64_t>(processInfo->writeTransferCount.QuadPart) +
                        static_cast<std::uint64_t>(processInfo->otherTransferCount.QuadPart);
                    processRecord.workingSetMB = static_cast<double>(processRecord.rawWorkingSetBytes) / (1024.0 * 1024.0);
                    processRecord.ramMB = static_cast<double>(processRecord.rawPrivateBytes) / (1024.0 * 1024.0);
                    processRecord.startTimeText = ks::str::fileTime100nsToLocalText(processRecord.creationTime100ns);
                    processRecord.dynamicCountersReady = true;

                    // Task Manager aligned fields:
                    // - These values reside in the same NtQuerySystemInformation buffer; reading them incurs no additional system calls.
                    // - Therefore, always populate regardless of whether the user displays the corresponding column to avoid a blank round when switching columns.
                    processRecord.basePriority = static_cast<std::int32_t>(processInfo->basePriority);
                    processRecord.cycleTime = static_cast<std::uint64_t>(processInfo->cycleTime);
                    processRecord.cycleTimeKnown = true;
                    processRecord.peakWorkingSetBytes = static_cast<std::uint64_t>(processInfo->peakWorkingSetSize);
                    processRecord.privateWorkingSetBytes =
                        (processInfo->workingSetPrivateSize.QuadPart > 0)
                        ? static_cast<std::uint64_t>(processInfo->workingSetPrivateSize.QuadPart)
                        : 0ULL;
                    processRecord.sharedWorkingSetBytes =
                        (processRecord.rawWorkingSetBytes > processRecord.privateWorkingSetBytes)
                        ? (processRecord.rawWorkingSetBytes - processRecord.privateWorkingSetBytes)
                        : 0ULL;
                    processRecord.privateWorkingSetKnown = true;
                    processRecord.commitSizeBytes = static_cast<std::uint64_t>(processInfo->pagefileUsage);
                    processRecord.peakCommitSizeBytes = static_cast<std::uint64_t>(processInfo->peakPagefileUsage);
                    processRecord.pagedPoolBytes = static_cast<std::uint64_t>(processInfo->quotaPagedPoolUsage);
                    processRecord.nonPagedPoolBytes = static_cast<std::uint64_t>(processInfo->quotaNonPagedPoolUsage);
                    processRecord.pageFaultCount = static_cast<std::uint64_t>(processInfo->pageFaultCount);
                    processRecord.hardFaultCount = static_cast<std::uint64_t>(processInfo->hardFaultCount);
                    processRecord.memoryDetailKnown = true;
                    processRecord.ioReadOperationCount = static_cast<std::uint64_t>(processInfo->readOperationCount.QuadPart);
                    processRecord.ioWriteOperationCount = static_cast<std::uint64_t>(processInfo->writeOperationCount.QuadPart);
                    processRecord.ioOtherOperationCount = static_cast<std::uint64_t>(processInfo->otherOperationCount.QuadPart);
                    processRecord.ioReadTransferBytes = static_cast<std::uint64_t>(processInfo->readTransferCount.QuadPart);
                    processRecord.ioWriteTransferBytes = static_cast<std::uint64_t>(processInfo->writeTransferCount.QuadPart);
                    processRecord.ioOtherTransferBytes = static_cast<std::uint64_t>(processInfo->otherTransferCount.QuadPart);
                    processRecord.ioDetailKnown = true;

                    // Running/Suspended state:
                    // - The thread array immediately follows the process record and is already in the buffer, requiring no further queries.
                    // - Judgment rule matches Task Manager: a process is considered 'suspended' only when
                    //   all threads are in the Waiting state with a wait reason of Suspended or WrSuspended.
                    applyProcessSuspendedStateFromThreadArray(
                        processRecord,
                        currentPointer,
                        informationBuffer.data(),
                        informationBuffer.size(),
                        static_cast<std::uint32_t>(processInfo->numberOfThreads));

                    if (processInfo->imageName.Buffer != nullptr && processInfo->imageName.Length > 0)
                    {
                        const std::wstring kImageName(
                            processInfo->imageName.Buffer,
                            static_cast<std::size_t>(processInfo->imageName.Length / sizeof(wchar_t)));
                        processRecord.processName = ks::str::utf16ToUtf8(kImageName);
                    }
                    else
                    {
                        // Common fallback naming for system kernel processes.
                        if (processRecord.pid == 0)
                        {
                            processRecord.processName = "System Idle Process";
                        }
                        else if (processRecord.pid == 4)
                        {
                            processRecord.processName = "System";
                        }
                        else
                        {
                            processRecord.processName = "Unknown";
                        }
                    }

                    processList.push_back(std::move(processRecord));

                    if (processInfo->nextEntryOffset == 0)
                    {
                        break;
                    }
                    currentPointer += processInfo->nextEntryOffset;
                }

                return processList;
            };

        // Execute according to the strategy and handle fallback logic.
        if (strategy == ProcessEnumStrategy::kSnapshotProcess32)
        {
            if (actualStrategyOut != nullptr)
            {
                *actualStrategyOut = ProcessEnumStrategy::kSnapshotProcess32;
            }
            std::vector<ProcessRecord> processList = kEnumerateBySnapshot();
            kApplyHandleCountFallback(processList);
            kApplyGpuUsageFallback(processList);
            return processList;
        }
        if (strategy == ProcessEnumStrategy::kNtQuerySystemInfo)
        {
            if (actualStrategyOut != nullptr)
            {
                *actualStrategyOut = ProcessEnumStrategy::kNtQuerySystemInfo;
            }
            std::vector<ProcessRecord> processList = kEnumerateByNtQuery();
            kApplyHandleCountFallback(processList);
            kApplyGpuUsageFallback(processList);
            return processList;
        }

        // Auto: Prefer NtQuery, fallback to Snapshot on failure.
        std::vector<ProcessRecord> processList = kEnumerateByNtQuery();
        if (!processList.empty())
        {
            if (actualStrategyOut != nullptr)
            {
                *actualStrategyOut = ProcessEnumStrategy::kNtQuerySystemInfo;
            }
            kApplyHandleCountFallback(processList);
            kApplyGpuUsageFallback(processList);
            return processList;
        }
        if (actualStrategyOut != nullptr)
        {
            *actualStrategyOut = ProcessEnumStrategy::kSnapshotProcess32;
        }
        processList = kEnumerateBySnapshot();
        kApplyHandleCountFallback(processList);
        kApplyGpuUsageFallback(processList);
        return processList;
    }

    std::vector<SystemThreadRecord> enumerateSystemThreads(
        bool* const usedNtQueryOut,
        std::string* const diagnosticTextOut)
    {
        // usedNtQueryOut usage: Report to the caller whether the NtQuery path was taken in this round.
        if (usedNtQueryOut != nullptr)
        {
            *usedNtQueryOut = false;
        }

        // diagnosticTextOut purpose: return the path explanation or failure reason for this round.
        if (diagnosticTextOut != nullptr)
        {
            diagnosticTextOut->clear();
        }

        // Phase 1: Prioritize attempting NtQuerySystemInformation(SystemExtendedProcessInformation).
        // This information class provides TEB and user stack boundaries beyond the base thread fields; falls back to the base class on failure.
        const auto kNtQuerySystemInformation = reinterpret_cast<NtQuerySystemInformationFn>(
            getNtdllProcAddress("NtQuerySystemInformation"));
        if (kNtQuerySystemInformation != nullptr)
        {
            const SYSTEM_INFORMATION_CLASS kPrimaryThreadInfoClass =
                static_cast<SYSTEM_INFORMATION_CLASS>(57);
            SYSTEM_INFORMATION_CLASS activeThreadInfoClass = kPrimaryThreadInfoClass;
            bool usedExtendedThreadInfo = true;
            ULONG bufferLength = 2 * 1024 * 1024;
            std::vector<BYTE> informationBuffer(bufferLength);
            NTSTATUS queryStatus = kNtQuerySystemInformation(
                activeThreadInfoClass,
                informationBuffer.data(),
                bufferLength,
                &bufferLength);

            while (queryStatus == kStatusInfoLengthMismatch)
            {
                bufferLength = (bufferLength * 3) / 2 + 64 * 1024;
                informationBuffer.resize(bufferLength);
                queryStatus = kNtQuerySystemInformation(
                    activeThreadInfoClass,
                    informationBuffer.data(),
                    bufferLength,
                    &bufferLength);
            }

            if (!NT_SUCCESS(queryStatus))
            {
                // Some restricted environments may reject extended information classes; falling back to the base class still ensures thread pages are available.
                activeThreadInfoClass = SystemProcessInformation;
                usedExtendedThreadInfo = false;
                bufferLength = 2 * 1024 * 1024;
                informationBuffer.assign(bufferLength, 0);
                queryStatus = kNtQuerySystemInformation(
                    activeThreadInfoClass,
                    informationBuffer.data(),
                    bufferLength,
                    &bufferLength);
                while (queryStatus == kStatusInfoLengthMismatch)
                {
                    bufferLength = (bufferLength * 3) / 2 + 64 * 1024;
                    informationBuffer.resize(bufferLength);
                    queryStatus = kNtQuerySystemInformation(
                        activeThreadInfoClass,
                        informationBuffer.data(),
                        bufferLength,
                        &bufferLength);
                }
            }

            if (NT_SUCCESS(queryStatus))
            {
                std::vector<SystemThreadRecord> threadList;

                // currentPointer: Used to sequentially traverse the NextEntryOffset linked list.
                BYTE* currentPointer = informationBuffer.data();
                while (currentPointer != nullptr)
                {
                    const auto* processInfo = reinterpret_cast<const SystemProcessInformationRecord*>(currentPointer);
                    const std::uint32_t kProcessPid = static_cast<std::uint32_t>(
                        reinterpret_cast<std::uintptr_t>(processInfo->uniqueProcessId));

                    // Purpose of processNameText: Reuse the same process name text for all threads under this process.
                    std::string processNameText;
                    if (processInfo->imageName.Buffer != nullptr && processInfo->imageName.Length > 0)
                    {
                        const std::wstring kImageName(
                            processInfo->imageName.Buffer,
                            static_cast<std::size_t>(processInfo->imageName.Length / sizeof(wchar_t)));
                        processNameText = ks::str::utf16ToUtf8(kImageName);
                    }
                    else if (kProcessPid == 0)
                    {
                        processNameText = "System Idle Process";
                    }
                    else if (kProcessPid == 4)
                    {
                        processNameText = "System";
                    }
                    else
                    {
                        processNameText = "Unknown";
                    }

                    // threadArrayPointer usage: Locates the thread array immediately following the current process entry.
                    const BYTE* threadArrayPointer = reinterpret_cast<const BYTE*>(processInfo + 1);
                    const std::size_t kThreadRecordSize = usedExtendedThreadInfo
                        ? sizeof(SystemExtendedThreadInformationRecord)
                        : sizeof(SystemThreadInformationRecord);
                    for (ULONG threadIndex = 0; threadIndex < processInfo->numberOfThreads; ++threadIndex)
                    {
                        const BYTE* threadRecordPointer =
                            threadArrayPointer + (static_cast<std::size_t>(threadIndex) * kThreadRecordSize);
                        const auto* threadInfo =
                            reinterpret_cast<const SystemThreadInformationRecord*>(threadRecordPointer);

                        SystemThreadRecord threadRecord{};
                        threadRecord.threadId = static_cast<std::uint32_t>(
                            reinterpret_cast<std::uintptr_t>(threadInfo->clientId.UniqueThread));
                        threadRecord.ownerPid = static_cast<std::uint32_t>(
                            reinterpret_cast<std::uintptr_t>(threadInfo->clientId.UniqueProcess));
                        if (threadRecord.ownerPid == 0)
                        {
                            threadRecord.ownerPid = kProcessPid;
                        }
                        threadRecord.ownerProcessName = processNameText;
                        threadRecord.startAddress = reinterpret_cast<std::uint64_t>(threadInfo->startAddress);
                        threadRecord.priority = static_cast<int>(threadInfo->priority);
                        threadRecord.basePriority = static_cast<int>(threadInfo->basePriority);
                        threadRecord.threadState = static_cast<std::uint32_t>(threadInfo->threadState);
                        threadRecord.waitReason = static_cast<std::uint32_t>(threadInfo->waitReason);
                        threadRecord.kernelTime100ns = static_cast<std::uint64_t>(threadInfo->reservedTime[0].QuadPart);
                        threadRecord.userTime100ns = static_cast<std::uint64_t>(threadInfo->reservedTime[1].QuadPart);
                        threadRecord.createTime100ns = static_cast<std::uint64_t>(threadInfo->reservedTime[2].QuadPart);
                        threadRecord.waitTimeTick = static_cast<std::uint32_t>(threadInfo->waitTime);
                        threadRecord.contextSwitchCount = static_cast<std::uint32_t>(threadInfo->contextSwitches);

                        if (usedExtendedThreadInfo)
                        {
                            const auto* extendedThreadInfo =
                                reinterpret_cast<const SystemExtendedThreadInformationRecord*>(threadRecordPointer);
                            threadRecord.stackBase = reinterpret_cast<std::uint64_t>(extendedThreadInfo->stackBase);
                            threadRecord.stackLimit = reinterpret_cast<std::uint64_t>(extendedThreadInfo->stackLimit);
                            threadRecord.win32StartAddress = reinterpret_cast<std::uint64_t>(extendedThreadInfo->win32StartAddress);
                            threadRecord.tebBaseAddress = reinterpret_cast<std::uint64_t>(extendedThreadInfo->tebBaseAddress);
                        }
                        threadList.push_back(std::move(threadRecord));
                    }

                    if (processInfo->nextEntryOffset == 0)
                    {
                        break;
                    }
                    currentPointer += processInfo->nextEntryOffset;
                }

                // Unified sort: by PID first, then TID, to ensure stable UI refresh order per cycle.
                std::sort(
                    threadList.begin(),
                    threadList.end(),
                    [](const SystemThreadRecord& leftRecord, const SystemThreadRecord& rightRecord)
                    {
                        if (leftRecord.ownerPid != rightRecord.ownerPid)
                        {
                            return leftRecord.ownerPid < rightRecord.ownerPid;
                        }
                        return leftRecord.threadId < rightRecord.threadId;
                    });

                if (usedNtQueryOut != nullptr)
                {
                    *usedNtQueryOut = true;
                }
                if (diagnosticTextOut != nullptr)
                {
                    *diagnosticTextOut = usedExtendedThreadInfo
                        ? "NtQuerySystemInformation(SystemExtendedProcessInformation) success"
                        : "NtQuerySystemInformation(SystemProcessInformation) success";
                }
                return threadList;
            }

            if (diagnosticTextOut != nullptr)
            {
                *diagnosticTextOut = formatNtStatusMessage(
                    queryStatus,
                    "NtQuerySystemInformation(SystemProcessInformation) failed");
            }
        }
        else if (diagnosticTextOut != nullptr)
        {
            *diagnosticTextOut = "NtQuerySystemInformation not available";
        }

        // Phase 2: Fall back to Toolhelp when the Nt path is unavailable (ensures functional availability).
        std::vector<SystemThreadRecord> threadList;
        HANDLE snapshotHandle = ::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snapshotHandle == INVALID_HANDLE_VALUE)
        {
            if (diagnosticTextOut != nullptr)
            {
                *diagnosticTextOut += " | Toolhelp fallback failed: "
                    + formatLastErrorMessage(::GetLastError());
            }
            return threadList;
        }

        // processNameCacheByPid purpose: Avoids redundant calls to getProcessNameByPid for the same PID.
        std::unordered_map<std::uint32_t, std::string> processNameCacheByPid;

        THREADENTRY32 threadEntry{};
        threadEntry.dwSize = sizeof(threadEntry);
        if (::Thread32First(snapshotHandle, &threadEntry) == FALSE)
        {
            if (diagnosticTextOut != nullptr)
            {
                *diagnosticTextOut += " | Thread32First failed: "
                    + formatLastErrorMessage(::GetLastError());
            }
            ::CloseHandle(snapshotHandle);
            return threadList;
        }

        do
        {
            SystemThreadRecord threadRecord{};
            threadRecord.threadId = static_cast<std::uint32_t>(threadEntry.th32ThreadID);
            threadRecord.ownerPid = static_cast<std::uint32_t>(threadEntry.th32OwnerProcessID);
            threadRecord.priority = static_cast<int>(threadEntry.tpBasePri);
            threadRecord.basePriority = static_cast<int>(threadEntry.tpBasePri);
            threadRecord.threadState = std::numeric_limits<std::uint32_t>::max();
            threadRecord.waitReason = std::numeric_limits<std::uint32_t>::max();

            // Toolhelp does not return cumulative thread time; use GetThreadTimes to fill the gap so that thread
            // CPU columns remain visible in the next iteration even when NtQuerySystemInformation is unavailable.
            HANDLE threadHandle = ::OpenThread(
                THREAD_QUERY_LIMITED_INFORMATION,
                FALSE,
                threadRecord.threadId);
            if (threadHandle != nullptr)
            {
                FILETIME createTime{};
                FILETIME exitTime{};
                FILETIME kernelTime{};
                FILETIME userTime{};
                if (::GetThreadTimes(
                    threadHandle,
                    &createTime,
                    &exitTime,
                    &kernelTime,
                    &userTime) != FALSE)
                {
                    threadRecord.createTime100ns = ks::str::fileTimeToUint64(
                        createTime.dwHighDateTime,
                        createTime.dwLowDateTime);
                    threadRecord.kernelTime100ns = ks::str::fileTimeToUint64(
                        kernelTime.dwHighDateTime,
                        kernelTime.dwLowDateTime);
                    threadRecord.userTime100ns = ks::str::fileTimeToUint64(
                        userTime.dwHighDateTime,
                        userTime.dwLowDateTime);
                }
                ::CloseHandle(threadHandle);
            }

            auto processNameIt = processNameCacheByPid.find(threadRecord.ownerPid);
            if (processNameIt == processNameCacheByPid.end())
            {
                std::string processNameText = getProcessNameByPid(threadRecord.ownerPid);
                if (processNameText.empty())
                {
                    processNameText = "Unknown";
                }
                processNameIt = processNameCacheByPid.emplace(
                    threadRecord.ownerPid,
                    std::move(processNameText)).first;
            }
            threadRecord.ownerProcessName = processNameIt->second;
            threadList.push_back(std::move(threadRecord));
        } while (::Thread32Next(snapshotHandle, &threadEntry) != FALSE);

        ::CloseHandle(snapshotHandle);

        std::sort(
            threadList.begin(),
            threadList.end(),
            [](const SystemThreadRecord& leftRecord, const SystemThreadRecord& rightRecord)
            {
                if (leftRecord.ownerPid != rightRecord.ownerPid)
                {
                    return leftRecord.ownerPid < rightRecord.ownerPid;
                }
                return leftRecord.threadId < rightRecord.threadId;
            });

        if (diagnosticTextOut != nullptr)
        {
            *diagnosticTextOut += " | Toolhelp fallback success";
        }
        return threadList;
    }

    std::string queryProcessPathByPid(const std::uint32_t pid)
    {
        if (pid == 0)
        {
            return std::string();
        }

        const HANDLE kProcessHandle = ::OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION,
            FALSE,
            toDwordPid(pid));
        if (kProcessHandle == nullptr)
        {
            return std::string();
        }

        std::string processPath = queryProcessPathByHandle(kProcessHandle);
        ::CloseHandle(kProcessHandle);
        return processPath;
    }

    std::string getProcessNameByPid(const std::uint32_t pid)
    {
        // Prefer extracting the filename from the path; fall back to snapshot enumeration on failure.
        const std::string kProcessPath = queryProcessPathByPid(pid);
        if (!kProcessPath.empty())
        {
            return extractFileNameFromPath(kProcessPath);
        }

        const std::vector<ProcessRecord> kProcessList = enumerateProcesses(ProcessEnumStrategy::kSnapshotProcess32);
        for (const ProcessRecord& processRecord : kProcessList)
        {
            if (processRecord.pid == pid)
            {
                return processRecord.processName;
            }
        }
        return std::string();
    }

    bool executeTaskKill(const std::uint32_t pid, const bool forceKill, std::string* const errorMessage)
    {
        // Execute via cmd /C taskkill to ensure behavior matches user manual commands.
        std::wstring commandLine = L"cmd.exe /C taskkill /PID " + std::to_wstring(pid);
        if (forceKill)
        {
            commandLine += L" /F";
        }

        STARTUPINFOW startupInfo{};
        startupInfo.cb = sizeof(startupInfo);
        PROCESS_INFORMATION processInfo{};

        std::vector<wchar_t> mutableCommandLine(commandLine.begin(), commandLine.end());
        mutableCommandLine.push_back(L'\0');

        const BOOL kCreateResult = ::CreateProcessW(
            nullptr,
            mutableCommandLine.data(),
            nullptr,
            nullptr,
            FALSE,
            CREATE_NO_WINDOW,
            nullptr,
            nullptr,
            &startupInfo,
            &processInfo);
        if (kCreateResult == FALSE)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "CreateProcess(taskkill) failed: " + formatLastErrorMessage(::GetLastError());
            }
            return false;
        }

        const DWORD kWaitResult = ::WaitForSingleObject(processInfo.hProcess, 10000);
        if (kWaitResult != WAIT_OBJECT_0)
        {
            const DWORD kWaitError = kWaitResult == WAIT_FAILED ? ::GetLastError() : ERROR_GEN_FAILURE;
            ::CloseHandle(processInfo.hThread);
            ::CloseHandle(processInfo.hProcess);
            if (errorMessage != nullptr)
            {
                *errorMessage = kWaitResult == WAIT_TIMEOUT
                    ? "taskkill timed out."
                    : "WaitForSingleObject(taskkill) failed: " + formatLastErrorMessage(kWaitError);
            }
            return false;
        }

        DWORD exitCode = 0;
        if (::GetExitCodeProcess(processInfo.hProcess, &exitCode) == FALSE)
        {
            const DWORD kExitCodeError = ::GetLastError();
            ::CloseHandle(processInfo.hThread);
            ::CloseHandle(processInfo.hProcess);
            if (errorMessage != nullptr)
            {
                *errorMessage = "GetExitCodeProcess(taskkill) failed: " + formatLastErrorMessage(kExitCodeError);
            }
            return false;
        }

        ::CloseHandle(processInfo.hThread);
        ::CloseHandle(processInfo.hProcess);

        if (exitCode == 0)
        {
            return true;
        }

        if (errorMessage != nullptr)
        {
            std::ostringstream stream;
            stream << "taskkill failed, exit code=" << exitCode;
            *errorMessage = stream.str();
        }
        return false;
    }

    bool terminateProcessByWin32(const std::uint32_t pid, std::string* const errorMessage)
    {
        const HANDLE kProcessHandle = ::OpenProcess(PROCESS_TERMINATE, FALSE, toDwordPid(pid));
        if (kProcessHandle == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "OpenProcess(PROCESS_TERMINATE) failed: " + formatLastErrorMessage(::GetLastError());
            }
            return false;
        }

        const BOOL kTerminateResult = ::TerminateProcess(kProcessHandle, 1);
        const DWORD kTerminateError = ::GetLastError();
        ::CloseHandle(kProcessHandle);

        if (kTerminateResult != FALSE)
        {
            return true;
        }

        if (errorMessage != nullptr)
        {
            *errorMessage = "TerminateProcess failed: " + formatLastErrorMessage(kTerminateError);
        }
        return false;
    }

    bool terminateProcessByWin32IfCreationTimeMatches(
        const std::uint32_t pid,
        const std::uint64_t expectedCreationTime100ns,
        std::string* const errorMessage)
    {
        if (pid == 0U || expectedCreationTime100ns == 0U)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "process identity is unavailable";
            }
            return false;
        }

        const HANDLE kProcessHandle = ::OpenProcess(
            PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION,
            FALSE,
            toDwordPid(pid));
        if (kProcessHandle == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "OpenProcess(for identity-verified terminate) failed: " +
                    formatLastErrorMessage(::GetLastError());
            }
            return false;
        }

        FILETIME creationTime{};
        FILETIME exitTime{};
        FILETIME kernelTime{};
        FILETIME userTime{};
        const BOOL kQueryOk = ::GetProcessTimes(
            kProcessHandle,
            &creationTime,
            &exitTime,
            &kernelTime,
            &userTime);
        const DWORD kQueryError = kQueryOk != FALSE ? ERROR_SUCCESS : ::GetLastError();
        const std::uint64_t kActualCreationTime100ns = kQueryOk != FALSE
            ? ks::str::fileTimeToUint64(
                creationTime.dwHighDateTime,
                creationTime.dwLowDateTime)
            : 0U;
        if (kQueryOk == FALSE ||
            kActualCreationTime100ns == 0U ||
            kActualCreationTime100ns != expectedCreationTime100ns)
        {
            ::CloseHandle(kProcessHandle);
            if (errorMessage != nullptr)
            {
                *errorMessage = kQueryOk == FALSE
                    ? "GetProcessTimes failed: " + formatLastErrorMessage(kQueryError)
                    : "process identity changed (PID was reused); termination skipped.";
            }
            return false;
        }

        const BOOL kTerminateResult = ::TerminateProcess(kProcessHandle, 1);
        const DWORD kTerminateError = kTerminateResult != FALSE ? ERROR_SUCCESS : ::GetLastError();
        ::CloseHandle(kProcessHandle);
        if (kTerminateResult != FALSE)
        {
            return true;
        }

        if (errorMessage != nullptr)
        {
            *errorMessage = "TerminateProcess failed: " + formatLastErrorMessage(kTerminateError);
        }
        return false;
    }

    bool terminateProcessByNtNative(const std::uint32_t pid, std::string* const errorMessage)
    {
        // Prefer NtTerminateProcess; fall back to ZwTerminateProcess if missing.
        auto ntTerminateProcess = reinterpret_cast<NtTerminateProcessFn>(
            getNtdllProcAddress("NtTerminateProcess"));
        if (ntTerminateProcess == nullptr)
        {
            ntTerminateProcess = reinterpret_cast<NtTerminateProcessFn>(
                getNtdllProcAddress("ZwTerminateProcess"));
        }
        if (ntTerminateProcess == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "NtTerminateProcess / ZwTerminateProcess not available.";
            }
            return false;
        }

        const HANDLE kProcessHandle = ::OpenProcess(PROCESS_TERMINATE, FALSE, toDwordPid(pid));
        if (kProcessHandle == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "OpenProcess(PROCESS_TERMINATE) failed: " + formatLastErrorMessage(::GetLastError());
            }
            return false;
        }

        const NTSTATUS kTerminateStatus = ntTerminateProcess(kProcessHandle, static_cast<NTSTATUS>(1));
        ::CloseHandle(kProcessHandle);
        if (NT_SUCCESS(kTerminateStatus))
        {
            return true;
        }

        if (errorMessage != nullptr)
        {
            *errorMessage = formatNtStatusMessage(kTerminateStatus, "NtTerminateProcess failed");
        }
        return false;
    }

    bool terminateProcessByWtsApi(const std::uint32_t pid, std::string* const errorMessage)
    {
        using WtsTerminateProcessFn = BOOL(WINAPI*)(HANDLE, DWORD, DWORD);

        static HMODULE wtsApiModule = ::LoadLibraryW(L"Wtsapi32.dll");
        if (wtsApiModule == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "LoadLibrary(Wtsapi32.dll) failed: " + formatLastErrorMessage(::GetLastError());
            }
            return false;
        }

        static WtsTerminateProcessFn wtsTerminateProcess = reinterpret_cast<WtsTerminateProcessFn>(
            ::GetProcAddress(wtsApiModule, "WTSTerminateProcess"));
        if (wtsTerminateProcess == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "GetProcAddress(WTSTerminateProcess) failed: " + formatLastErrorMessage(::GetLastError());
            }
            return false;
        }

        // Passing nullptr indicates the current server (equivalent to WTS_CURRENT_SERVER_HANDLE).
        const BOOL kTerminateResult = wtsTerminateProcess(nullptr, toDwordPid(pid), 1);
        if (kTerminateResult != FALSE)
        {
            return true;
        }

        if (errorMessage != nullptr)
        {
            *errorMessage = "WTSTerminateProcess failed: " + formatLastErrorMessage(::GetLastError());
        }
        return false;
    }

    bool terminateProcessByWinStationApi(const std::uint32_t pid, std::string* const errorMessage)
    {
        using WinStationTerminateProcessFn = BOOLEAN(WINAPI*)(HANDLE, ULONG, ULONG);

        static HMODULE winstaModule = ::LoadLibraryW(L"winsta.dll");
        if (winstaModule == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "LoadLibrary(winsta.dll) failed: " + formatLastErrorMessage(::GetLastError());
            }
            return false;
        }

        static WinStationTerminateProcessFn winStationTerminateProcess = reinterpret_cast<WinStationTerminateProcessFn>(
            ::GetProcAddress(winstaModule, "WinStationTerminateProcess"));
        if (winStationTerminateProcess == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "GetProcAddress(WinStationTerminateProcess) failed: " + formatLastErrorMessage(::GetLastError());
            }
            return false;
        }

        const BOOLEAN kTerminateResult = winStationTerminateProcess(nullptr, static_cast<ULONG>(pid), 1UL);
        if (kTerminateResult != FALSE)
        {
            return true;
        }

        if (errorMessage != nullptr)
        {
            *errorMessage = "WinStationTerminateProcess failed: " + formatLastErrorMessage(::GetLastError());
        }
        return false;
    }

    bool terminateProcessByJobObject(const std::uint32_t pid, std::string* const errorMessage)
    {
        const HANDLE kProcessHandle = ::OpenProcess(
            PROCESS_SET_QUOTA | PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION,
            FALSE,
            toDwordPid(pid));
        if (kProcessHandle == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "OpenProcess(for job terminate) failed: " + formatLastErrorMessage(::GetLastError());
            }
            return false;
        }

        const HANDLE kJobHandle = ::CreateJobObjectW(nullptr, nullptr);
        if (kJobHandle == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "CreateJobObjectW failed: " + formatLastErrorMessage(::GetLastError());
            }
            ::CloseHandle(kProcessHandle);
            return false;
        }

        const BOOL kAssignResult = ::AssignProcessToJobObject(kJobHandle, kProcessHandle);
        const DWORD kAssignError = ::GetLastError();
        if (kAssignResult == FALSE)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "AssignProcessToJobObject failed: " + formatLastErrorMessage(kAssignError);
            }
            ::CloseHandle(kJobHandle);
            ::CloseHandle(kProcessHandle);
            return false;
        }

        const BOOL kTerminateResult = ::TerminateJobObject(kJobHandle, 1);
        const DWORD kTerminateError = ::GetLastError();
        ::CloseHandle(kJobHandle);
        ::CloseHandle(kProcessHandle);
        if (kTerminateResult != FALSE)
        {
            return true;
        }

        if (errorMessage != nullptr)
        {
            *errorMessage = "TerminateJobObject failed: " + formatLastErrorMessage(kTerminateError);
        }
        return false;
    }

    bool terminateProcessByNtJobObject(const std::uint32_t pid, std::string* const errorMessage)
    {
        // Prefer NtTerminateJobObject; fall back to ZwTerminateJobObject if missing.
        auto ntTerminateJobObject = reinterpret_cast<NtTerminateJobObjectFn>(
            getNtdllProcAddress("NtTerminateJobObject"));
        if (ntTerminateJobObject == nullptr)
        {
            ntTerminateJobObject = reinterpret_cast<NtTerminateJobObjectFn>(
                getNtdllProcAddress("ZwTerminateJobObject"));
        }
        if (ntTerminateJobObject == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "NtTerminateJobObject / ZwTerminateJobObject not available.";
            }
            return false;
        }

        const HANDLE kProcessHandle = ::OpenProcess(
            PROCESS_SET_QUOTA | PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION,
            FALSE,
            toDwordPid(pid));
        if (kProcessHandle == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "OpenProcess(for nt job terminate) failed: " + formatLastErrorMessage(::GetLastError());
            }
            return false;
        }

        const HANDLE kJobHandle = ::CreateJobObjectW(nullptr, nullptr);
        if (kJobHandle == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "CreateJobObjectW failed: " + formatLastErrorMessage(::GetLastError());
            }
            ::CloseHandle(kProcessHandle);
            return false;
        }

        const BOOL kAssignResult = ::AssignProcessToJobObject(kJobHandle, kProcessHandle);
        const DWORD kAssignError = ::GetLastError();
        if (kAssignResult == FALSE)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "AssignProcessToJobObject failed: " + formatLastErrorMessage(kAssignError);
            }
            ::CloseHandle(kJobHandle);
            ::CloseHandle(kProcessHandle);
            return false;
        }

        const NTSTATUS kTerminateStatus = ntTerminateJobObject(kJobHandle, static_cast<NTSTATUS>(1));
        ::CloseHandle(kJobHandle);
        ::CloseHandle(kProcessHandle);
        if (NT_SUCCESS(kTerminateStatus))
        {
            return true;
        }

        if (errorMessage != nullptr)
        {
            *errorMessage = formatNtStatusMessage(kTerminateStatus, "NtTerminateJobObject failed");
        }
        return false;
    }

    bool terminateProcessByRestartManager(
        const std::uint32_t pid,
        const bool forceShutdown,
        std::string* const errorMessage)
    {
        using RmStartSessionFn = DWORD(WINAPI*)(DWORD*, DWORD, WCHAR*);
        using RmRegisterResourcesFn = DWORD(WINAPI*)(DWORD, UINT, LPCWSTR*, UINT, RM_UNIQUE_PROCESS*, UINT, LPCWSTR*);
        using RmShutdownFn = DWORD(WINAPI*)(DWORD, ULONG, RM_WRITE_STATUS_CALLBACK);
        using RmEndSessionFn = DWORD(WINAPI*)(DWORD);

        static HMODULE restartManagerModule = ::LoadLibraryW(L"Rstrtmgr.dll");
        if (restartManagerModule == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "LoadLibrary(Rstrtmgr.dll) failed: " + formatLastErrorMessage(::GetLastError());
            }
            return false;
        }

        static RmStartSessionFn rmStartSession = reinterpret_cast<RmStartSessionFn>(
            ::GetProcAddress(restartManagerModule, "RmStartSession"));
        static RmRegisterResourcesFn rmRegisterResources = reinterpret_cast<RmRegisterResourcesFn>(
            ::GetProcAddress(restartManagerModule, "RmRegisterResources"));
        static RmShutdownFn rmShutdown = reinterpret_cast<RmShutdownFn>(
            ::GetProcAddress(restartManagerModule, "RmShutdown"));
        static RmEndSessionFn rmEndSession = reinterpret_cast<RmEndSessionFn>(
            ::GetProcAddress(restartManagerModule, "RmEndSession"));
        if (rmStartSession == nullptr ||
            rmRegisterResources == nullptr ||
            rmShutdown == nullptr ||
            rmEndSession == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "Restart Manager function export missing.";
            }
            return false;
        }

        DWORD sessionHandle = 0;
        WCHAR sessionKey[CCH_RM_SESSION_KEY + 1] = {};
        const DWORD kStartResult = rmStartSession(&sessionHandle, 0, sessionKey);
        if (kStartResult != ERROR_SUCCESS)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "RmStartSession failed: code=" + std::to_string(kStartResult);
            }
            return false;
        }

        FILETIME processStartTime{};
        if (!queryProcessStartTimeByPid(pid, &processStartTime))
        {
            rmEndSession(sessionHandle);
            if (errorMessage != nullptr)
            {
                *errorMessage = "QueryProcessStartTimeByPid failed.";
            }
            return false;
        }

        RM_UNIQUE_PROCESS uniqueProcess{};
        uniqueProcess.dwProcessId = toDwordPid(pid);
        uniqueProcess.ProcessStartTime = processStartTime;

        const DWORD kRegisterResult = rmRegisterResources(
            sessionHandle,
            0,
            nullptr,
            1,
            &uniqueProcess,
            0,
            nullptr);
        if (kRegisterResult != ERROR_SUCCESS)
        {
            rmEndSession(sessionHandle);
            if (errorMessage != nullptr)
            {
                *errorMessage = "RmRegisterResources failed: code=" + std::to_string(kRegisterResult);
            }
            return false;
        }

        const ULONG kShutdownFlags = forceShutdown ? kRestartManagerForceShutdownFlag : 0UL;
        const DWORD kShutdownResult = rmShutdown(sessionHandle, kShutdownFlags, nullptr);
        const DWORD kEndResult = rmEndSession(sessionHandle);
        if (kShutdownResult == ERROR_SUCCESS)
        {
            return true;
        }

        if (errorMessage != nullptr)
        {
            std::ostringstream stream;
            stream << "RmShutdown failed: code=" << kShutdownResult
                << ", RmEndSession=" << kEndResult;
            *errorMessage = stream.str();
        }
        return false;
    }

    bool terminateProcessByDuplicateHandlePseudo(const std::uint32_t pid, std::string* const errorMessage)
    {
        // Open the target process first with 'duplicate handle' permissions.
        const HANDLE kTargetProcessHandle = ::OpenProcess(PROCESS_DUP_HANDLE, FALSE, toDwordPid(pid));
        if (kTargetProcessHandle == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "OpenProcess(PROCESS_DUP_HANDLE) failed: " + formatLastErrorMessage(::GetLastError());
            }
            return false;
        }

        // Duplicate the pseudo-handle (-1) from the target process to the current process to obtain the target process's real handle.
        HANDLE duplicatedProcessHandle = nullptr;
        const BOOL kDuplicateResult = ::DuplicateHandle(
            kTargetProcessHandle,
            reinterpret_cast<HANDLE>(static_cast<LONG_PTR>(-1)),
            ::GetCurrentProcess(),
            &duplicatedProcessHandle,
            0,
            FALSE,
            DUPLICATE_SAME_ACCESS);
        const DWORD kDuplicateError = ::GetLastError();
        ::CloseHandle(kTargetProcessHandle);
        if (kDuplicateResult == FALSE || duplicatedProcessHandle == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "DuplicateHandle(-1 pseudo handle) failed: " + formatLastErrorMessage(kDuplicateError);
            }
            return false;
        }

        const BOOL kTerminateResult = ::TerminateProcess(duplicatedProcessHandle, 1);
        const DWORD kTerminateError = ::GetLastError();
        ::CloseHandle(duplicatedProcessHandle);
        if (kTerminateResult != FALSE)
        {
            return true;
        }

        if (errorMessage != nullptr)
        {
            *errorMessage = "TerminateProcess(duplicated handle) failed: " + formatLastErrorMessage(kTerminateError);
        }
        return false;
    }

    bool terminateAllThreadsByPid(const std::uint32_t pid, std::string* const errorMessage)
    {
        HANDLE snapshotHandle = ::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snapshotHandle == INVALID_HANDLE_VALUE)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "CreateToolhelp32Snapshot(THREAD) failed: " + formatLastErrorMessage(::GetLastError());
            }
            return false;
        }

        THREADENTRY32 threadEntry{};
        threadEntry.dwSize = sizeof(threadEntry);
        if (::Thread32First(snapshotHandle, &threadEntry) == FALSE)
        {
            ::CloseHandle(snapshotHandle);
            if (errorMessage != nullptr)
            {
                *errorMessage = "Thread32First failed: " + formatLastErrorMessage(::GetLastError());
            }
            return false;
        }

        std::uint32_t terminatedCount = 0;
        do
        {
            if (threadEntry.th32OwnerProcessID != pid)
            {
                continue;
            }

            const HANDLE kThreadHandle = ::OpenThread(THREAD_TERMINATE, FALSE, threadEntry.th32ThreadID);
            if (kThreadHandle == nullptr)
            {
                continue;
            }

            if (::TerminateThread(kThreadHandle, 1) != FALSE)
            {
                ++terminatedCount;
            }
            ::CloseHandle(kThreadHandle);
        } while (::Thread32Next(snapshotHandle, &threadEntry) != FALSE);

        ::CloseHandle(snapshotHandle);
        if (terminatedCount > 0)
        {
            return true;
        }

        if (errorMessage != nullptr)
        {
            *errorMessage = "No thread terminated (possible access denied or process has exited).";
        }
        return false;
    }

    bool terminateAllThreadsByPidNtNative(const std::uint32_t pid, std::string* const errorMessage)
    {
        // Prefer NtTerminateThread; fall back to ZwTerminateThread if missing.
        auto ntTerminateThread = reinterpret_cast<NtTerminateThreadFn>(
            getNtdllProcAddress("NtTerminateThread"));
        if (ntTerminateThread == nullptr)
        {
            ntTerminateThread = reinterpret_cast<NtTerminateThreadFn>(
                getNtdllProcAddress("ZwTerminateThread"));
        }
        if (ntTerminateThread == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "NtTerminateThread / ZwTerminateThread not available.";
            }
            return false;
        }

        HANDLE snapshotHandle = ::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snapshotHandle == INVALID_HANDLE_VALUE)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "CreateToolhelp32Snapshot(THREAD) failed: " + formatLastErrorMessage(::GetLastError());
            }
            return false;
        }

        THREADENTRY32 threadEntry{};
        threadEntry.dwSize = sizeof(threadEntry);
        if (::Thread32First(snapshotHandle, &threadEntry) == FALSE)
        {
            ::CloseHandle(snapshotHandle);
            if (errorMessage != nullptr)
            {
                *errorMessage = "Thread32First failed: " + formatLastErrorMessage(::GetLastError());
            }
            return false;
        }

        std::uint32_t terminatedCount = 0;
        do
        {
            if (threadEntry.th32OwnerProcessID != pid)
            {
                continue;
            }

            const HANDLE kThreadHandle = ::OpenThread(THREAD_TERMINATE, FALSE, threadEntry.th32ThreadID);
            if (kThreadHandle == nullptr)
            {
                continue;
            }

            const NTSTATUS kTerminateStatus = ntTerminateThread(kThreadHandle, static_cast<NTSTATUS>(1));
            if (NT_SUCCESS(kTerminateStatus))
            {
                ++terminatedCount;
            }
            ::CloseHandle(kThreadHandle);
        } while (::Thread32Next(snapshotHandle, &threadEntry) != FALSE);

        ::CloseHandle(snapshotHandle);
        if (terminatedCount > 0)
        {
            return true;
        }

        if (errorMessage != nullptr)
        {
            *errorMessage = "No thread terminated via NtTerminateThread.";
        }
        return false;
    }

    bool terminateProcessByDebugAttach(const std::uint32_t pid, std::string* const errorMessage)
    {
        // Debug attachment typically requires SeDebugPrivilege; attempt to enable it first.
        enablePrivilege(SE_DEBUG_NAME);

        const BOOL kAttachResult = ::DebugActiveProcess(toDwordPid(pid));
        if (kAttachResult == FALSE)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "DebugActiveProcess failed: " + formatLastErrorMessage(::GetLastError());
            }
            return false;
        }

        // Sets DebugSetProcessKillOnExit(0) following the example link.
        const BOOL kSetKillOnExitResult = ::DebugSetProcessKillOnExit(FALSE);
        const DWORD kSetKillOnExitError = ::GetLastError();

        // Avoid the current process holding the debug relationship for too long; attempt to detach immediately here.
        const BOOL kStopResult = ::DebugActiveProcessStop(toDwordPid(pid));
        const DWORD kStopError = ::GetLastError();

        if (kSetKillOnExitResult != FALSE && kStopResult != FALSE)
        {
            return true;
        }

        if (errorMessage != nullptr)
        {
            std::ostringstream stream;
            if (kSetKillOnExitResult == FALSE)
            {
                stream << "DebugSetProcessKillOnExit(FALSE) failed: "
                    << formatLastErrorMessage(kSetKillOnExitError);
            }
            if (kStopResult == FALSE)
            {
                if (!stream.str().empty())
                {
                    stream << "; ";
                }
                stream << "DebugActiveProcessStop failed: "
                    << formatLastErrorMessage(kStopError);
            }
            *errorMessage = stream.str();
        }
        return false;
    }

    bool terminateProcessByNtsdCommand(const std::uint32_t pid, std::string* const errorMessage)
    {
        // Command format: ntsd -c q -p <pid>, which attaches and immediately executes 'q' to exit.
        std::wstring commandLine = L"cmd.exe /C ntsd -c q -p " + std::to_wstring(pid);
        std::vector<wchar_t> mutableCommandLine(commandLine.begin(), commandLine.end());
        mutableCommandLine.push_back(L'\0');

        STARTUPINFOW startupInfo{};
        startupInfo.cb = sizeof(startupInfo);
        PROCESS_INFORMATION processInfo{};
        const BOOL kCreateResult = ::CreateProcessW(
            nullptr,
            mutableCommandLine.data(),
            nullptr,
            nullptr,
            FALSE,
            CREATE_NO_WINDOW,
            nullptr,
            nullptr,
            &startupInfo,
            &processInfo);
        if (kCreateResult == FALSE)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "CreateProcess(ntsd) failed: " + formatLastErrorMessage(::GetLastError());
            }
            return false;
        }

        const DWORD kWaitResult = ::WaitForSingleObject(processInfo.hProcess, 15000);
        if (kWaitResult != WAIT_OBJECT_0)
        {
            ::CloseHandle(processInfo.hThread);
            ::CloseHandle(processInfo.hProcess);
            if (errorMessage != nullptr)
            {
                *errorMessage = "ntsd wait timeout or failed, waitResult=" + std::to_string(kWaitResult);
            }
            return false;
        }

        DWORD exitCode = 0;
        const BOOL kExitCodeOk = ::GetExitCodeProcess(processInfo.hProcess, &exitCode);
        const DWORD kExitCodeError = kExitCodeOk != FALSE ? ERROR_SUCCESS : ::GetLastError();
        ::CloseHandle(processInfo.hThread);
        ::CloseHandle(processInfo.hProcess);
        if (kExitCodeOk == FALSE)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "GetExitCodeProcess(ntsd) failed: " + formatLastErrorMessage(kExitCodeError);
            }
            return false;
        }
        if (exitCode == 0)
        {
            return true;
        }

        if (errorMessage != nullptr)
        {
            *errorMessage = "ntsd exit code=" + std::to_string(exitCode);
        }
        return false;
    }

    bool terminateProcessByNtUnmapNtdll(const std::uint32_t pid, std::string* const errorMessage)
    {
        auto ntUnmapViewOfSection = reinterpret_cast<NtUnmapViewOfSectionFn>(
            getNtdllProcAddress("NtUnmapViewOfSection"));
        if (ntUnmapViewOfSection == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "NtUnmapViewOfSection not available.";
            }
            return false;
        }

        void* ntdllBaseAddress = nullptr;
        if (!queryModuleBaseAddressBySnapshot(pid, L"ntdll.dll", &ntdllBaseAddress) || ntdllBaseAddress == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "QueryModuleBaseAddressBySnapshot(ntdll.dll) failed.";
            }
            return false;
        }

        const HANDLE kProcessHandle = ::OpenProcess(PROCESS_VM_OPERATION, FALSE, toDwordPid(pid));
        if (kProcessHandle == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "OpenProcess(PROCESS_VM_OPERATION) failed: " + formatLastErrorMessage(::GetLastError());
            }
            return false;
        }

        const NTSTATUS kUnmapStatus = ntUnmapViewOfSection(kProcessHandle, ntdllBaseAddress);
        ::CloseHandle(kProcessHandle);
        if (NT_SUCCESS(kUnmapStatus))
        {
            return true;
        }

        if (errorMessage != nullptr)
        {
            *errorMessage = formatNtStatusMessage(kUnmapStatus, "NtUnmapViewOfSection failed");
        }
        return false;
    }

    bool injectInvalidShellcode(const std::uint32_t pid, std::string* const errorMessage)
    {
        const HANDLE kProcessHandle = ::OpenProcess(
            PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
            FALSE,
            toDwordPid(pid));
        if (kProcessHandle == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "OpenProcess(for injection) failed: " + formatLastErrorMessage(::GetLastError());
            }
            return false;
        }

        // Invalid shellcode: UD2 + RET, used to trigger an illegal instruction exception.
        const BYTE kInvalidShellcode[] = { 0x0F, 0x0B, 0xC3 };
        void* remoteMemory = ::VirtualAllocEx(
            kProcessHandle,
            nullptr,
            sizeof(kInvalidShellcode),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE);
        if (remoteMemory == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "VirtualAllocEx failed: " + formatLastErrorMessage(::GetLastError());
            }
            ::CloseHandle(kProcessHandle);
            return false;
        }

        SIZE_T bytesWritten = 0;
        const BOOL kWriteResult = ::WriteProcessMemory(
            kProcessHandle,
            remoteMemory,
            kInvalidShellcode,
            sizeof(kInvalidShellcode),
            &bytesWritten);
        if (kWriteResult == FALSE || bytesWritten != sizeof(kInvalidShellcode))
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "WriteProcessMemory failed: " + formatLastErrorMessage(::GetLastError());
            }
            ::VirtualFreeEx(kProcessHandle, remoteMemory, 0, MEM_RELEASE);
            ::CloseHandle(kProcessHandle);
            return false;
        }

        // Start a remote thread to execute invalid code.
        const HANDLE kRemoteThread = ::CreateRemoteThread(
            kProcessHandle,
            nullptr,
            0,
            reinterpret_cast<LPTHREAD_START_ROUTINE>(remoteMemory),
            nullptr,
            0,
            nullptr);
        if (kRemoteThread == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "CreateRemoteThread failed: " + formatLastErrorMessage(::GetLastError());
            }
            ::VirtualFreeEx(kProcessHandle, remoteMemory, 0, MEM_RELEASE);
            ::CloseHandle(kProcessHandle);
            return false;
        }

        ::WaitForSingleObject(kRemoteThread, 1500);
        ::CloseHandle(kRemoteThread);
        ::CloseHandle(kProcessHandle);

        // Do not release remoteMemory here: the target process may have crashed or exited, making the release meaningless.
        return true;
    }

    bool invokeSuspendResumeProcessIfCreationTimeMatches(
        const std::uint32_t pid,
        const std::uint64_t expectedCreationTime100ns,
        const bool resume,
        std::string* const errorMessage)
    {
        if (pid == 0U || expectedCreationTime100ns == 0U)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "process identity is unavailable";
            }
            return false;
        }

        const auto kProcessRoutine = reinterpret_cast<NtSuspendProcessFn>(
            getNtdllProcAddress(resume ? "NtResumeProcess" : "NtSuspendProcess"));
        if (kProcessRoutine == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = resume
                    ? "NtResumeProcess not available."
                    : "NtSuspendProcess not available.";
            }
            return false;
        }

        const HANDLE kProcessHandle = ::OpenProcess(
            kProcessSuspendResumeAccess | PROCESS_QUERY_LIMITED_INFORMATION,
            FALSE,
            toDwordPid(pid));
        if (kProcessHandle == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "OpenProcess(for identity-verified suspend/resume) failed: " +
                    formatLastErrorMessage(::GetLastError());
            }
            return false;
        }

        FILETIME creationTime{};
        FILETIME exitTime{};
        FILETIME kernelTime{};
        FILETIME userTime{};
        const BOOL kQueryOk = ::GetProcessTimes(
            kProcessHandle,
            &creationTime,
            &exitTime,
            &kernelTime,
            &userTime);
        const DWORD kQueryError = kQueryOk != FALSE ? ERROR_SUCCESS : ::GetLastError();
        const std::uint64_t kActualCreationTime100ns = kQueryOk != FALSE
            ? ks::str::fileTimeToUint64(
                creationTime.dwHighDateTime,
                creationTime.dwLowDateTime)
            : 0U;
        if (kQueryOk == FALSE ||
            kActualCreationTime100ns == 0U ||
            kActualCreationTime100ns != expectedCreationTime100ns)
        {
            ::CloseHandle(kProcessHandle);
            if (errorMessage != nullptr)
            {
                *errorMessage = kQueryOk == FALSE
                    ? "GetProcessTimes failed: " + formatLastErrorMessage(kQueryError)
                    : "process identity changed (PID was reused); action skipped.";
            }
            return false;
        }

        const NTSTATUS kActionStatus = kProcessRoutine(kProcessHandle);
        ::CloseHandle(kProcessHandle);
        if (NT_SUCCESS(kActionStatus))
        {
            return true;
        }

        if (errorMessage != nullptr)
        {
            *errorMessage = formatNtStatusMessage(
                kActionStatus,
                resume ? "NtResumeProcess failed" : "NtSuspendProcess failed");
        }
        return false;
    }

    bool suspendProcess(const std::uint32_t pid, std::string* const errorMessage)
    {
        const auto kNtSuspendProcess = reinterpret_cast<NtSuspendProcessFn>(
            getNtdllProcAddress("NtSuspendProcess"));
        if (kNtSuspendProcess == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "NtSuspendProcess not available.";
            }
            return false;
        }

        const HANDLE kProcessHandle = ::OpenProcess(kProcessSuspendResumeAccess, FALSE, toDwordPid(pid));
        if (kProcessHandle == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "OpenProcess(PROCESS_SUSPEND_RESUME) failed: " + formatLastErrorMessage(::GetLastError());
            }
            return false;
        }

        const NTSTATUS kSuspendStatus = kNtSuspendProcess(kProcessHandle);
        ::CloseHandle(kProcessHandle);
        if (NT_SUCCESS(kSuspendStatus))
        {
            return true;
        }

        if (errorMessage != nullptr)
        {
            *errorMessage = formatNtStatusMessage(kSuspendStatus, "NtSuspendProcess failed");
        }
        return false;
    }

    bool resumeProcess(const std::uint32_t pid, std::string* const errorMessage)
    {
        const auto kNtResumeProcess = reinterpret_cast<NtResumeProcessFn>(
            getNtdllProcAddress("NtResumeProcess"));
        if (kNtResumeProcess == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "NtResumeProcess not available.";
            }
            return false;
        }

        const HANDLE kProcessHandle = ::OpenProcess(kProcessSuspendResumeAccess, FALSE, toDwordPid(pid));
        if (kProcessHandle == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "OpenProcess(PROCESS_SUSPEND_RESUME) failed: " + formatLastErrorMessage(::GetLastError());
            }
            return false;
        }

        const NTSTATUS kResumeStatus = kNtResumeProcess(kProcessHandle);
        ::CloseHandle(kProcessHandle);
        if (NT_SUCCESS(kResumeStatus))
        {
            return true;
        }

        if (errorMessage != nullptr)
        {
            *errorMessage = formatNtStatusMessage(kResumeStatus, "NtResumeProcess failed");
        }
        return false;
    }

    bool suspendProcessIfCreationTimeMatches(
        const std::uint32_t pid,
        const std::uint64_t expectedCreationTime100ns,
        std::string* const errorMessage)
    {
        return invokeSuspendResumeProcessIfCreationTimeMatches(
            pid,
            expectedCreationTime100ns,
            false,
            errorMessage);
    }

    bool resumeProcessIfCreationTimeMatches(
        const std::uint32_t pid,
        const std::uint64_t expectedCreationTime100ns,
        std::string* const errorMessage)
    {
        return invokeSuspendResumeProcessIfCreationTimeMatches(
            pid,
            expectedCreationTime100ns,
            true,
            errorMessage);
    }

    bool setProcessCriticalFlag(const std::uint32_t pid, const bool enableCritical, std::string* const errorMessage)
    {
        const auto kNtSetInformationProcess = reinterpret_cast<NtSetInformationProcessFn>(
            getNtdllProcAddress("NtSetInformationProcess"));
        if (kNtSetInformationProcess == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "NtSetInformationProcess not available.";
            }
            return false;
        }

        // Setting up critical processes typically requires SeDebugPrivilege.
        enablePrivilege(SE_DEBUG_NAME);

        const HANDLE kProcessHandle = ::OpenProcess(PROCESS_SET_INFORMATION, FALSE, toDwordPid(pid));
        if (kProcessHandle == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "OpenProcess(PROCESS_SET_INFORMATION) failed: " + formatLastErrorMessage(::GetLastError());
            }
            return false;
        }

        ULONG criticalFlag = enableCritical ? 1UL : 0UL;
        const NTSTATUS kSetStatus = kNtSetInformationProcess(
            kProcessHandle,
            kProcessBreakOnTerminationInfoClass,
            &criticalFlag,
            static_cast<ULONG>(sizeof(criticalFlag)));
        ::CloseHandle(kProcessHandle);

        if (NT_SUCCESS(kSetStatus))
        {
            return true;
        }

        if (errorMessage != nullptr)
        {
            *errorMessage = formatNtStatusMessage(
                kSetStatus,
                enableCritical ? "Set critical process failed" : "Clear critical process failed");
        }
        return false;
    }

    bool setProcessPriority(const std::uint32_t pid, const ProcessPriorityLevel priorityLevel, std::string* const errorMessage)
    {
        DWORD priorityClass = NORMAL_PRIORITY_CLASS;
        switch (priorityLevel)
        {
        case ProcessPriorityLevel::kIdle:
            priorityClass = IDLE_PRIORITY_CLASS;
            break;
        case ProcessPriorityLevel::kBelowNormal:
            priorityClass = BELOW_NORMAL_PRIORITY_CLASS;
            break;
        case ProcessPriorityLevel::kNormal:
            priorityClass = NORMAL_PRIORITY_CLASS;
            break;
        case ProcessPriorityLevel::kAboveNormal:
            priorityClass = ABOVE_NORMAL_PRIORITY_CLASS;
            break;
        case ProcessPriorityLevel::kHigh:
            priorityClass = HIGH_PRIORITY_CLASS;
            break;
        case ProcessPriorityLevel::kRealtime:
            priorityClass = REALTIME_PRIORITY_CLASS;
            break;
        default:
            priorityClass = NORMAL_PRIORITY_CLASS;
            break;
        }

        const HANDLE kProcessHandle = ::OpenProcess(PROCESS_SET_INFORMATION, FALSE, toDwordPid(pid));
        if (kProcessHandle == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "OpenProcess(PROCESS_SET_INFORMATION) failed: " + formatLastErrorMessage(::GetLastError());
            }
            return false;
        }

        const BOOL kSetResult = ::SetPriorityClass(kProcessHandle, priorityClass);
        const DWORD kSetError = ::GetLastError();
        ::CloseHandle(kProcessHandle);
        if (kSetResult != FALSE)
        {
            return true;
        }

        if (errorMessage != nullptr)
        {
            *errorMessage = "SetPriorityClass failed: " + formatLastErrorMessage(kSetError);
        }
        return false;
    }

    bool setProcessEfficiencyMode(
        const std::uint32_t pid,
        const bool enableEfficiencyMode,
        std::string* const errorMessage)
    {
        HMODULE kernel32Module = ::GetModuleHandleW(L"kernel32.dll");
        const auto kSetProcessInformation = reinterpret_cast<SetProcessInformationFn>(
            kernel32Module != nullptr ? ::GetProcAddress(kernel32Module, "SetProcessInformation") : nullptr);
        if (kSetProcessInformation == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "SetProcessInformation(ProcessPowerThrottling) is not available.";
            }
            return false;
        }

        const HANDLE kProcessHandle = ::OpenProcess(PROCESS_SET_INFORMATION, FALSE, toDwordPid(pid));
        if (kProcessHandle == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "OpenProcess(PROCESS_SET_INFORMATION) failed: " + formatLastErrorMessage(::GetLastError());
            }
            return false;
        }

        ProcessPowerThrottlingStateNative powerState{};
        powerState.version = kProcessPowerThrottlingCurrentVersion;
        powerState.controlMask = kProcessPowerThrottlingExecutionSpeed;
        powerState.stateMask = enableEfficiencyMode ? kProcessPowerThrottlingExecutionSpeed : 0UL;
        const BOOL kSetOk = kSetProcessInformation(
            kProcessHandle,
            kProcessPowerThrottlingInfoClass,
            &powerState,
            static_cast<DWORD>(sizeof(powerState)));
        const DWORD kSetError = ::GetLastError();
        ::CloseHandle(kProcessHandle);
        if (kSetOk != FALSE)
        {
            return true;
        }

        if (errorMessage != nullptr)
        {
            *errorMessage = "SetProcessInformation(ProcessPowerThrottling) failed: "
                + formatLastErrorMessage(kSetError);
        }
        return false;
    }

    bool openProcessFolder(const std::uint32_t pid, std::string* const errorMessage)
    {
        const std::string kProcessPath = queryProcessPathByPid(pid);
        if (kProcessPath.empty())
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "Process path is empty or inaccessible.";
            }
            return false;
        }

        return openInExplorerByPath(kProcessPath, errorMessage);
    }

    bool queryProcessStaticDetailByPid(
        const std::uint32_t pid,
        ProcessRecord& outRecord,
        const bool includeSignatureCheck)
    {
        outRecord = ProcessRecord{};
        outRecord.pid = pid;
        outRecord.processName = getProcessNameByPid(pid);

        // Refresh dynamic counters first to ensure fields like creation time and memory are as available as possible.
        refreshProcessDynamicCounters(outRecord);

        // Supplement static details again:
        // - When includeSignatureCheck=false, skip WinVerifyTrust.
        // - Purpose: Used for quick UI window opening or background phased refresh.
        const bool kStaticOk = fillProcessStaticDetails(outRecord, includeSignatureCheck);

        // Final fallback: if the process name is still empty, use the PID text as a placeholder.
        if (outRecord.processName.empty())
        {
            outRecord.processName = "PID_" + std::to_string(pid);
        }
        return kStaticOk;
    }

    static ProcessModuleSnapshot enumerateProcessModulesAndThreadsInternal(
        const std::uint32_t pid,
        const bool includeSignatureCheck,
        const bool requireVerifiedProcessIdentity,
        const std::uint64_t expectedCreationTime100ns)
    {
        ProcessModuleSnapshot snapshot;
        snapshot.modules.clear();
        snapshot.threads.clear();
        snapshot.diagnosticText.clear();

        // appendDiagnostic:
        // - Accumulate module refresh diagnostic text;
        // - Concatenate multi-segment errors with " | " to allow the UI to display the complete context at once.
        const auto kAppendDiagnostic = [&snapshot](const std::string& text)
            {
                if (text.empty())
                {
                    return;
                }
                if (!snapshot.diagnosticText.empty())
                {
                    snapshot.diagnosticText += " | ";
                }
                snapshot.diagnosticText += text;
            };

        struct ScopedProcessIdentityHandle final
        {
            HANDLE handle = nullptr;
            ~ScopedProcessIdentityHandle()
            {
                if (handle != nullptr)
                {
                    ::CloseHandle(handle);
                }
            }
        } processIdentityHold;

        if (requireVerifiedProcessIdentity)
        {
            if (pid == 0U || expectedCreationTime100ns == 0U)
            {
                kAppendDiagnostic("process identity is unavailable; module snapshot skipped.");
                return snapshot;
            }

            processIdentityHold.handle = ::OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION,
                FALSE,
                toDwordPid(pid));
            if (processIdentityHold.handle == nullptr)
            {
                kAppendDiagnostic(
                    "OpenProcess(for module identity) failed: " +
                    formatLastErrorMessage(::GetLastError()));
                return snapshot;
            }

            FILETIME creationTime{};
            FILETIME exitTime{};
            FILETIME kernelTime{};
            FILETIME userTime{};
            const BOOL kIdentityQueryOk = ::GetProcessTimes(
                processIdentityHold.handle,
                &creationTime,
                &exitTime,
                &kernelTime,
                &userTime);
            const DWORD kIdentityQueryError = kIdentityQueryOk != FALSE ? ERROR_SUCCESS : ::GetLastError();
            const std::uint64_t kActualCreationTime100ns = kIdentityQueryOk != FALSE
                ? ks::str::fileTimeToUint64(creationTime.dwHighDateTime, creationTime.dwLowDateTime)
                : 0U;
            if (kIdentityQueryOk == FALSE ||
                kActualCreationTime100ns == 0U ||
                kActualCreationTime100ns != expectedCreationTime100ns)
            {
                kAppendDiagnostic(kIdentityQueryOk == FALSE
                    ? "GetProcessTimes(for module identity) failed: " + formatLastErrorMessage(kIdentityQueryError)
                    : "process identity changed (PID was reused); module snapshot skipped.");
                return snapshot;
            }
        }

        // fillModuleSignature:
        // - Uniformly populate module signature display text, vendor, and trust marker.
        // - When includeSignatureCheck is false, the state remains Pending (fast mode).
        const auto kFillModuleSignature = [includeSignatureCheck](ProcessModuleRecord& moduleRecord)
            {
                if (includeSignatureCheck)
                {
                    const FileSignatureInfo kSignatureInfo = queryFileSignatureInfo(moduleRecord.modulePath);
                    moduleRecord.signatureState = kSignatureInfo.displayText.empty() ? "Unknown" : kSignatureInfo.displayText;
                    moduleRecord.signaturePublisher = kSignatureInfo.publisher;
                    moduleRecord.signatureTrusted = kSignatureInfo.trustedByWindows;
                    return;
                }
                moduleRecord.signatureState = "Pending";
                moduleRecord.signaturePublisher.clear();
                moduleRecord.signatureTrusted = false;
            };

        // enumerate threads first to populate ThreadID information for module rows.
        std::vector<std::uint32_t> threadIdList;
        std::uint32_t representativeThreadId = 0U;
        std::uint64_t representativeThreadCreationTime100ns = 0U;
        HANDLE threadSnapshotHandle = ::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (threadSnapshotHandle != INVALID_HANDLE_VALUE)
        {
            THREADENTRY32 threadEntry{};
            threadEntry.dwSize = sizeof(threadEntry);
            if (::Thread32First(threadSnapshotHandle, &threadEntry) != FALSE)
            {
                do
                {
                    if (threadEntry.th32OwnerProcessID != pid)
                    {
                        continue;
                    }

                    ProcessThreadRecord threadRecord{};
                    threadRecord.threadId = static_cast<std::uint32_t>(threadEntry.th32ThreadID);
                    threadRecord.ownerPid = static_cast<std::uint32_t>(threadEntry.th32OwnerProcessID);
                    threadRecord.basePriority = static_cast<int>(threadEntry.tpBasePri);
                    threadRecord.stateText = "Running";
                    snapshot.threads.push_back(threadRecord);
                    threadIdList.push_back(threadRecord.threadId);

                    // Use only threads whose owner and creation time can be verified on the same thread object as the entry point for module actions.
                    if (representativeThreadId == 0U)
                    {
                        const HANDLE kRepresentativeThreadHandle = ::OpenThread(
                            THREAD_QUERY_LIMITED_INFORMATION,
                            FALSE,
                            toDwordPid(threadRecord.threadId));
                        if (kRepresentativeThreadHandle != nullptr)
                        {
                            const DWORD kActualOwnerPid = ::GetProcessIdOfThread(kRepresentativeThreadHandle);
                            FILETIME creationTime{};
                            FILETIME exitTime{};
                            FILETIME kernelTime{};
                            FILETIME userTime{};
                            const BOOL kTimeQueryOk = ::GetThreadTimes(
                                kRepresentativeThreadHandle,
                                &creationTime,
                                &exitTime,
                                &kernelTime,
                                &userTime);
                            const std::uint64_t kCreationTime100ns = kTimeQueryOk != FALSE
                                ? ks::str::fileTimeToUint64(
                                    creationTime.dwHighDateTime,
                                    creationTime.dwLowDateTime)
                                : 0U;
                            if (kActualOwnerPid == toDwordPid(pid) && kCreationTime100ns != 0U)
                            {
                                representativeThreadId = threadRecord.threadId;
                                representativeThreadCreationTime100ns = kCreationTime100ns;
                            }
                            ::CloseHandle(kRepresentativeThreadHandle);
                        }
                    }
                } while (::Thread32Next(threadSnapshotHandle, &threadEntry) != FALSE);
            }
            ::CloseHandle(threadSnapshotHandle);
        }

        // First priority: Toolhelp module enumeration (standard path).
        bool moduleEnumerated = false;
        HANDLE moduleSnapshotHandle = ::CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, toDwordPid(pid));
        if (moduleSnapshotHandle == INVALID_HANDLE_VALUE)
        {
            kAppendDiagnostic("CreateToolhelp32Snapshot(module) failed: " + formatLastErrorMessage(::GetLastError()));
        }
        else
        {
            MODULEENTRY32W moduleEntry{};
            moduleEntry.dwSize = sizeof(moduleEntry);
            if (::Module32FirstW(moduleSnapshotHandle, &moduleEntry) == FALSE)
            {
                kAppendDiagnostic("Module32FirstW failed: " + formatLastErrorMessage(::GetLastError()));
            }
            else
            {
                do
                {
                    ProcessModuleRecord moduleRecord{};
                    moduleRecord.moduleName = ks::str::utf16ToUtf8(moduleEntry.szModule);
                    moduleRecord.modulePath = ks::str::utf16ToUtf8(moduleEntry.szExePath);
                    moduleRecord.moduleBaseAddress = reinterpret_cast<std::uint64_t>(moduleEntry.modBaseAddr);
                    moduleRecord.moduleSizeBytes = static_cast<std::uint32_t>(moduleEntry.modBaseSize);
                    moduleRecord.entryPointRva = queryImageEntryPointRvaByPath(moduleRecord.modulePath);
                    moduleRecord.runningState = "Loaded";
                    kFillModuleSignature(moduleRecord);

                    moduleRecord.representativeThreadId = representativeThreadId;
                    moduleRecord.representativeThreadCreationTime100ns = representativeThreadCreationTime100ns;
                    moduleRecord.threadIdText = buildThreadIdSummaryText(threadIdList);
                    snapshot.modules.push_back(std::move(moduleRecord));
                } while (::Module32NextW(moduleSnapshotHandle, &moduleEntry) != FALSE);
                moduleEnumerated = true;
                kAppendDiagnostic("Module source: Toolhelp");
            }
            ::CloseHandle(moduleSnapshotHandle);
        }

        // When Toolhelp fails, fall back to PSAPI to resolve the issue where modules are always 0.
        if (!moduleEnumerated)
        {
            const HANDLE kProcessHandle = ::OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                FALSE,
                toDwordPid(pid));
            if (kProcessHandle == nullptr)
            {
                kAppendDiagnostic("PSAPI fallback open process failed: " + formatLastErrorMessage(::GetLastError()));
                return snapshot;
            }

            std::vector<HMODULE> moduleHandleBuffer(2048);
            DWORD bytesNeeded = 0;
            if (::EnumProcessModulesEx(
                kProcessHandle,
                moduleHandleBuffer.data(),
                static_cast<DWORD>(moduleHandleBuffer.size() * sizeof(HMODULE)),
                &bytesNeeded,
                LIST_MODULES_ALL) == FALSE)
            {
                kAppendDiagnostic("EnumProcessModulesEx failed: " + formatLastErrorMessage(::GetLastError()));
                ::CloseHandle(kProcessHandle);
                return snapshot;
            }

            const std::size_t kModuleCount = static_cast<std::size_t>(bytesNeeded / sizeof(HMODULE));
            if (kModuleCount > moduleHandleBuffer.size())
            {
                moduleHandleBuffer.resize(kModuleCount);
                if (::EnumProcessModulesEx(
                    kProcessHandle,
                    moduleHandleBuffer.data(),
                    static_cast<DWORD>(moduleHandleBuffer.size() * sizeof(HMODULE)),
                    &bytesNeeded,
                    LIST_MODULES_ALL) == FALSE)
                {
                    kAppendDiagnostic("EnumProcessModulesEx(second pass) failed: " + formatLastErrorMessage(::GetLastError()));
                    ::CloseHandle(kProcessHandle);
                    return snapshot;
                }
            }

            std::vector<wchar_t> modulePathBuffer(32768U, L'\0');
            for (std::size_t moduleIndex = 0; moduleIndex < kModuleCount; ++moduleIndex)
            {
                const HMODULE kModuleHandle = moduleHandleBuffer[moduleIndex];
                if (kModuleHandle == nullptr)
                {
                    continue;
                }

                const DWORD kModulePathLength = ::GetModuleFileNameExW(
                    kProcessHandle,
                    kModuleHandle,
                    modulePathBuffer.data(),
                    static_cast<DWORD>(modulePathBuffer.size()));
                if (kModulePathLength == 0)
                {
                    continue;
                }

                MODULEINFO moduleInfo{};
                if (::GetModuleInformation(
                    kProcessHandle,
                    kModuleHandle,
                    &moduleInfo,
                    static_cast<DWORD>(sizeof(moduleInfo))) == FALSE)
                {
                    continue;
                }

                ProcessModuleRecord moduleRecord{};
                moduleRecord.modulePath = ks::str::utf16ToUtf8(std::wstring(modulePathBuffer.data(), kModulePathLength));
                moduleRecord.moduleName = extractFileNameFromPath(moduleRecord.modulePath);
                moduleRecord.moduleBaseAddress = reinterpret_cast<std::uint64_t>(moduleInfo.lpBaseOfDll);
                moduleRecord.moduleSizeBytes = static_cast<std::uint32_t>(moduleInfo.SizeOfImage);

                const std::uint64_t kEntryPointAddress = reinterpret_cast<std::uint64_t>(moduleInfo.EntryPoint);
                const std::uint64_t kBaseAddress = moduleRecord.moduleBaseAddress;
                if (kEntryPointAddress >= kBaseAddress)
                {
                    moduleRecord.entryPointRva = static_cast<std::uint32_t>(kEntryPointAddress - kBaseAddress);
                }
                else
                {
                    moduleRecord.entryPointRva = queryImageEntryPointRvaByPath(moduleRecord.modulePath);
                }

                moduleRecord.runningState = "Loaded";
                kFillModuleSignature(moduleRecord);
                moduleRecord.representativeThreadId = representativeThreadId;
                moduleRecord.representativeThreadCreationTime100ns = representativeThreadCreationTime100ns;
                moduleRecord.threadIdText = buildThreadIdSummaryText(threadIdList);
                snapshot.modules.push_back(std::move(moduleRecord));
            }

            moduleEnumerated = true;
            kAppendDiagnostic("Module source: PSAPI fallback");
            ::CloseHandle(kProcessHandle);
        }

        if (!moduleEnumerated)
        {
            kAppendDiagnostic("No module enumeration path succeeded.");
        }
        else if (snapshot.modules.empty())
        {
            kAppendDiagnostic("Module enumeration succeeded but module count is 0.");
        }

        return snapshot;
    }

    ProcessModuleSnapshot enumerateProcessModulesAndThreads(
        const std::uint32_t pid,
        const bool includeSignatureCheck)
    {
        return enumerateProcessModulesAndThreadsInternal(
            pid,
            includeSignatureCheck,
            false,
            0U);
    }

    ProcessModuleSnapshot enumerateProcessModulesAndThreadsIfIdentityMatches(
        const std::uint32_t pid,
        const std::uint64_t expectedCreationTime100ns,
        const bool includeSignatureCheck)
    {
        return enumerateProcessModulesAndThreadsInternal(
            pid,
            includeSignatureCheck,
            true,
            expectedCreationTime100ns);
    }

    bool unloadModuleByBaseAddressIfIdentityMatches(
        const std::uint32_t pid,
        const std::uint64_t expectedCreationTime100ns,
        const std::uint64_t moduleBaseAddress,
        std::string* const errorMessage)
    {
        const HANDLE kProcessHandle = ::OpenProcess(
            PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ,
            FALSE,
            toDwordPid(pid));
        if (kProcessHandle == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "OpenProcess(for unload module) failed: " + formatLastErrorMessage(::GetLastError());
            }
            return false;
        }

        FILETIME creationTime{};
        FILETIME exitTime{};
        FILETIME kernelTime{};
        FILETIME userTime{};
        const BOOL kIdentityQueryOk = ::GetProcessTimes(
            kProcessHandle,
            &creationTime,
            &exitTime,
            &kernelTime,
            &userTime);
        const DWORD kIdentityQueryError = kIdentityQueryOk != FALSE ? ERROR_SUCCESS : ::GetLastError();
        const std::uint64_t kActualCreationTime100ns = kIdentityQueryOk != FALSE
            ? ks::str::fileTimeToUint64(creationTime.dwHighDateTime, creationTime.dwLowDateTime)
            : 0U;
        if (expectedCreationTime100ns == 0U ||
            kIdentityQueryOk == FALSE ||
            kActualCreationTime100ns == 0U ||
            kActualCreationTime100ns != expectedCreationTime100ns)
        {
            ::CloseHandle(kProcessHandle);
            if (errorMessage != nullptr)
            {
                *errorMessage = kIdentityQueryOk == FALSE
                    ? "GetProcessTimes(for unload module) failed: " + formatLastErrorMessage(kIdentityQueryError)
                    : "process identity changed or is unavailable; module unload skipped.";
            }
            return false;
        }

        const HMODULE kKernel32Module = ::GetModuleHandleW(L"kernel32.dll");
        FARPROC freeLibraryAddress = kKernel32Module != nullptr
            ? ::GetProcAddress(kKernel32Module, "FreeLibrary")
            : nullptr;
        if (freeLibraryAddress == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "GetProcAddress(FreeLibrary) failed.";
            }
            ::CloseHandle(kProcessHandle);
            return false;
        }

        HANDLE remoteThread = ::CreateRemoteThread(
            kProcessHandle,
            nullptr,
            0,
            reinterpret_cast<LPTHREAD_START_ROUTINE>(freeLibraryAddress),
            reinterpret_cast<LPVOID>(moduleBaseAddress),
            0,
            nullptr);
        if (remoteThread == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "CreateRemoteThread(FreeLibrary) failed: " + formatLastErrorMessage(::GetLastError());
            }
            ::CloseHandle(kProcessHandle);
            return false;
        }

        constexpr DWORD kUnloadWaitTimeoutMs = 5000;
        const DWORD kWaitResult = ::WaitForSingleObject(remoteThread, kUnloadWaitTimeoutMs);
        const DWORD kWaitError = kWaitResult == WAIT_FAILED ? ::GetLastError() : ERROR_SUCCESS;
        if (kWaitResult != WAIT_OBJECT_0)
        {
            ::CloseHandle(remoteThread);
            ::CloseHandle(kProcessHandle);
            if (errorMessage != nullptr)
            {
                if (kWaitResult == WAIT_TIMEOUT)
                {
                    *errorMessage = "FreeLibrary remote thread did not finish within "
                        + std::to_string(kUnloadWaitTimeoutMs)
                        + " ms; unload state is unknown.";
                }
                else if (kWaitResult == WAIT_FAILED)
                {
                    *errorMessage = "WaitForSingleObject(FreeLibrary) failed: "
                        + formatLastErrorMessage(kWaitError);
                }
                else
                {
                    *errorMessage = "WaitForSingleObject(FreeLibrary) returned unexpected result: "
                        + std::to_string(kWaitResult);
                }
            }
            return false;
        }

        DWORD threadExitCode = 0;
        const BOOL kExitCodeOk = ::GetExitCodeThread(remoteThread, &threadExitCode);
        const DWORD kExitCodeError = kExitCodeOk != FALSE ? ERROR_SUCCESS : ::GetLastError();
        ::CloseHandle(remoteThread);
        ::CloseHandle(kProcessHandle);

        if (kExitCodeOk == FALSE)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "GetExitCodeThread(FreeLibrary) failed: "
                    + formatLastErrorMessage(kExitCodeError);
            }
            return false;
        }

        if (threadExitCode != 0)
        {
            return true;
        }

        if (errorMessage != nullptr)
        {
            *errorMessage = "FreeLibrary returned 0, module may not be unloaded.";
        }
        return false;
    }

    bool suspendThreadById(const std::uint32_t threadId, std::string* const errorMessage)
    {
        const HANDLE kThreadHandle = ::OpenThread(THREAD_SUSPEND_RESUME, FALSE, threadId);
        if (kThreadHandle == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "OpenThread(THREAD_SUSPEND_RESUME) failed: " + formatLastErrorMessage(::GetLastError());
            }
            return false;
        }

        const DWORD kSuspendResult = ::SuspendThread(kThreadHandle);
        ::CloseHandle(kThreadHandle);
        if (kSuspendResult != static_cast<DWORD>(-1))
        {
            return true;
        }

        if (errorMessage != nullptr)
        {
            *errorMessage = "SuspendThread failed: " + formatLastErrorMessage(::GetLastError());
        }
        return false;
    }

    bool resumeThreadById(const std::uint32_t threadId, std::string* const errorMessage)
    {
        const HANDLE kThreadHandle = ::OpenThread(THREAD_SUSPEND_RESUME, FALSE, threadId);
        if (kThreadHandle == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "OpenThread(THREAD_SUSPEND_RESUME) failed: " + formatLastErrorMessage(::GetLastError());
            }
            return false;
        }

        const DWORD kResumeResult = ::ResumeThread(kThreadHandle);
        ::CloseHandle(kThreadHandle);
        if (kResumeResult != static_cast<DWORD>(-1))
        {
            return true;
        }

        if (errorMessage != nullptr)
        {
            *errorMessage = "ResumeThread failed: " + formatLastErrorMessage(::GetLastError());
        }
        return false;
    }

    bool terminateThreadById(const std::uint32_t threadId, std::string* const errorMessage)
    {
        const HANDLE kThreadHandle = ::OpenThread(THREAD_TERMINATE, FALSE, threadId);
        if (kThreadHandle == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "OpenThread(THREAD_TERMINATE) failed: " + formatLastErrorMessage(::GetLastError());
            }
            return false;
        }

        const BOOL kTerminateResult = ::TerminateThread(kThreadHandle, 1);
        const DWORD kTerminateError = ::GetLastError();
        ::CloseHandle(kThreadHandle);
        if (kTerminateResult != FALSE)
        {
            return true;
        }

        if (errorMessage != nullptr)
        {
            *errorMessage = "TerminateThread failed: " + formatLastErrorMessage(kTerminateError);
        }
        return false;
    }

    namespace
    {
        enum class ThreadIdentityAction
        {
            kSuspend,
            kResume,
            kTerminate
        };

        bool applyThreadActionIfIdentityMatches(
            const std::uint32_t threadId,
            const std::uint32_t expectedOwnerPid,
            const std::uint64_t expectedCreationTime100ns,
            const ThreadIdentityAction action,
            std::string* const errorMessage)
        {
            if (threadId == 0U || expectedOwnerPid == 0U || expectedCreationTime100ns == 0U)
            {
                if (errorMessage != nullptr)
                {
                    *errorMessage = "thread identity is unavailable; action skipped.";
                }
                return false;
            }

            const DWORD kActionAccess = action == ThreadIdentityAction::kTerminate
                ? THREAD_TERMINATE
                : THREAD_SUSPEND_RESUME;
            const HANDLE kThreadHandle = ::OpenThread(
                kActionAccess | THREAD_QUERY_LIMITED_INFORMATION,
                FALSE,
                threadId);
            if (kThreadHandle == nullptr)
            {
                if (errorMessage != nullptr)
                {
                    *errorMessage = "OpenThread(for identity-verified action) failed: " +
                        formatLastErrorMessage(::GetLastError());
                }
                return false;
            }

            const DWORD kActualOwnerPid = ::GetProcessIdOfThread(kThreadHandle);
            const DWORD kOwnerQueryError = kActualOwnerPid != 0U ? ERROR_SUCCESS : ::GetLastError();
            FILETIME creationTime{};
            FILETIME exitTime{};
            FILETIME kernelTime{};
            FILETIME userTime{};
            const BOOL kTimeQueryOk = ::GetThreadTimes(
                kThreadHandle,
                &creationTime,
                &exitTime,
                &kernelTime,
                &userTime);
            const DWORD kTimeQueryError = kTimeQueryOk != FALSE ? ERROR_SUCCESS : ::GetLastError();
            const std::uint64_t kActualCreationTime100ns = kTimeQueryOk != FALSE
                ? ks::str::fileTimeToUint64(
                    creationTime.dwHighDateTime,
                    creationTime.dwLowDateTime)
                : 0U;
            if (kActualOwnerPid == 0U || kTimeQueryOk == FALSE ||
                kActualCreationTime100ns == 0U ||
                kActualOwnerPid != expectedOwnerPid ||
                kActualCreationTime100ns != expectedCreationTime100ns)
            {
                ::CloseHandle(kThreadHandle);
                if (errorMessage != nullptr)
                {
                    if (kActualOwnerPid == 0U)
                    {
                        *errorMessage = "GetProcessIdOfThread failed: " +
                            formatLastErrorMessage(kOwnerQueryError);
                    }
                    else if (kTimeQueryOk == FALSE)
                    {
                        *errorMessage = "GetThreadTimes failed: " +
                            formatLastErrorMessage(kTimeQueryError);
                    }
                    else if (kActualOwnerPid != expectedOwnerPid)
                    {
                        *errorMessage = "thread owner changed; action skipped.";
                    }
                    else
                    {
                        *errorMessage = "thread identity changed (TID was reused); action skipped.";
                    }
                }
                return false;
            }

            if (action == ThreadIdentityAction::kSuspend)
            {
                const DWORD kResult = ::SuspendThread(kThreadHandle);
                const DWORD kActionError = kResult == static_cast<DWORD>(-1)
                    ? ::GetLastError()
                    : ERROR_SUCCESS;
                ::CloseHandle(kThreadHandle);
                if (kResult != static_cast<DWORD>(-1))
                {
                    return true;
                }
                if (errorMessage != nullptr)
                {
                    *errorMessage = "SuspendThread failed: " + formatLastErrorMessage(kActionError);
                }
                return false;
            }

            if (action == ThreadIdentityAction::kResume)
            {
                const DWORD kResult = ::ResumeThread(kThreadHandle);
                const DWORD kActionError = kResult == static_cast<DWORD>(-1)
                    ? ::GetLastError()
                    : ERROR_SUCCESS;
                ::CloseHandle(kThreadHandle);
                if (kResult != static_cast<DWORD>(-1))
                {
                    return true;
                }
                if (errorMessage != nullptr)
                {
                    *errorMessage = "ResumeThread failed: " + formatLastErrorMessage(kActionError);
                }
                return false;
            }

            const BOOL kResult = ::TerminateThread(kThreadHandle, 1);
            const DWORD kActionError = kResult != FALSE ? ERROR_SUCCESS : ::GetLastError();
            ::CloseHandle(kThreadHandle);
            if (kResult != FALSE)
            {
                return true;
            }
            if (errorMessage != nullptr)
            {
                *errorMessage = "TerminateThread failed: " + formatLastErrorMessage(kActionError);
            }
            return false;
        }

        bool applyThreadActionIfProcessAndThreadIdentityMatches(
            const std::uint32_t threadId,
            const std::uint32_t expectedOwnerPid,
            const std::uint64_t expectedProcessCreationTime100ns,
            const std::uint64_t expectedThreadCreationTime100ns,
            const ThreadIdentityAction action,
            std::string* const errorMessage)
        {
            if (expectedOwnerPid == 0U || expectedProcessCreationTime100ns == 0U)
            {
                if (errorMessage != nullptr)
                {
                    *errorMessage = "process identity is unavailable; thread action skipped.";
                }
                return false;
            }

            const HANDLE kProcessHandle = ::OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION,
                FALSE,
                toDwordPid(expectedOwnerPid));
            if (kProcessHandle == nullptr)
            {
                if (errorMessage != nullptr)
                {
                    *errorMessage = "OpenProcess(for thread identity) failed: " +
                        formatLastErrorMessage(::GetLastError());
                }
                return false;
            }

            FILETIME creationTime{};
            FILETIME exitTime{};
            FILETIME kernelTime{};
            FILETIME userTime{};
            const BOOL kTimeQueryOk = ::GetProcessTimes(
                kProcessHandle,
                &creationTime,
                &exitTime,
                &kernelTime,
                &userTime);
            const DWORD kTimeQueryError = kTimeQueryOk != FALSE ? ERROR_SUCCESS : ::GetLastError();
            const std::uint64_t kActualProcessCreationTime100ns = kTimeQueryOk != FALSE
                ? ks::str::fileTimeToUint64(creationTime.dwHighDateTime, creationTime.dwLowDateTime)
                : 0U;
            if (kTimeQueryOk == FALSE ||
                kActualProcessCreationTime100ns == 0U ||
                kActualProcessCreationTime100ns != expectedProcessCreationTime100ns)
            {
                ::CloseHandle(kProcessHandle);
                if (errorMessage != nullptr)
                {
                    *errorMessage = kTimeQueryOk == FALSE
                        ? "GetProcessTimes(for thread identity) failed: " + formatLastErrorMessage(kTimeQueryError)
                        : "process identity changed (PID was reused); thread action skipped.";
                }
                return false;
            }

            const bool kActionOk = applyThreadActionIfIdentityMatches(
                threadId,
                expectedOwnerPid,
                expectedThreadCreationTime100ns,
                action,
                errorMessage);
            ::CloseHandle(kProcessHandle);
            return kActionOk;
        }
    }

    bool suspendThreadIfIdentityMatches(
        const std::uint32_t threadId,
        const std::uint32_t expectedOwnerPid,
        const std::uint64_t expectedCreationTime100ns,
        std::string* const errorMessage)
    {
        return applyThreadActionIfIdentityMatches(
            threadId,
            expectedOwnerPid,
            expectedCreationTime100ns,
            ThreadIdentityAction::kSuspend,
            errorMessage);
    }

    bool resumeThreadIfIdentityMatches(
        const std::uint32_t threadId,
        const std::uint32_t expectedOwnerPid,
        const std::uint64_t expectedCreationTime100ns,
        std::string* const errorMessage)
    {
        return applyThreadActionIfIdentityMatches(
            threadId,
            expectedOwnerPid,
            expectedCreationTime100ns,
            ThreadIdentityAction::kResume,
            errorMessage);
    }

    bool terminateThreadIfIdentityMatches(
        const std::uint32_t threadId,
        const std::uint32_t expectedOwnerPid,
        const std::uint64_t expectedCreationTime100ns,
        std::string* const errorMessage)
    {
        return applyThreadActionIfIdentityMatches(
            threadId,
            expectedOwnerPid,
            expectedCreationTime100ns,
            ThreadIdentityAction::kTerminate,
            errorMessage);
    }

    bool suspendThreadIfProcessAndThreadIdentityMatches(
        const std::uint32_t threadId,
        const std::uint32_t expectedOwnerPid,
        const std::uint64_t expectedProcessCreationTime100ns,
        const std::uint64_t expectedThreadCreationTime100ns,
        std::string* const errorMessage)
    {
        return applyThreadActionIfProcessAndThreadIdentityMatches(
            threadId,
            expectedOwnerPid,
            expectedProcessCreationTime100ns,
            expectedThreadCreationTime100ns,
            ThreadIdentityAction::kSuspend,
            errorMessage);
    }

    bool resumeThreadIfProcessAndThreadIdentityMatches(
        const std::uint32_t threadId,
        const std::uint32_t expectedOwnerPid,
        const std::uint64_t expectedProcessCreationTime100ns,
        const std::uint64_t expectedThreadCreationTime100ns,
        std::string* const errorMessage)
    {
        return applyThreadActionIfProcessAndThreadIdentityMatches(
            threadId,
            expectedOwnerPid,
            expectedProcessCreationTime100ns,
            expectedThreadCreationTime100ns,
            ThreadIdentityAction::kResume,
            errorMessage);
    }

    bool terminateThreadIfProcessAndThreadIdentityMatches(
        const std::uint32_t threadId,
        const std::uint32_t expectedOwnerPid,
        const std::uint64_t expectedProcessCreationTime100ns,
        const std::uint64_t expectedThreadCreationTime100ns,
        std::string* const errorMessage)
    {
        return applyThreadActionIfProcessAndThreadIdentityMatches(
            threadId,
            expectedOwnerPid,
            expectedProcessCreationTime100ns,
            expectedThreadCreationTime100ns,
            ThreadIdentityAction::kTerminate,
            errorMessage);
    }

    bool injectDllByPath(const std::uint32_t pid, const std::string& dllPath, std::string* const errorMessage)
    {
        if (dllPath.empty())
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "DLL path is empty.";
            }
            return false;
        }

        const std::wstring kDllPathWide = ks::str::utf8ToUtf16(dllPath);
        if (kDllPathWide.empty())
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "DLL path UTF-8 -> UTF-16 conversion failed.";
            }
            return false;
        }

        const DWORD kPathAttributes = ::GetFileAttributesW(kDllPathWide.c_str());
        if (kPathAttributes == INVALID_FILE_ATTRIBUTES || (kPathAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "DLL path does not exist or points to a directory.";
            }
            return false;
        }

        const HANDLE kProcessHandle = ::OpenProcess(
            PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
            FALSE,
            toDwordPid(pid));
        if (kProcessHandle == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "OpenProcess(for DLL inject) failed: " + formatLastErrorMessage(::GetLastError());
            }
            return false;
        }

        const std::size_t kByteCount = (kDllPathWide.size() + 1) * sizeof(wchar_t);
        void* remotePathMemory = ::VirtualAllocEx(
            kProcessHandle,
            nullptr,
            kByteCount,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE);
        if (remotePathMemory == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "VirtualAllocEx(for DLL path) failed: " + formatLastErrorMessage(::GetLastError());
            }
            ::CloseHandle(kProcessHandle);
            return false;
        }

        SIZE_T bytesWritten = 0;
        if (::WriteProcessMemory(
            kProcessHandle,
            remotePathMemory,
            kDllPathWide.c_str(),
            kByteCount,
            &bytesWritten) == FALSE ||
            bytesWritten != kByteCount)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "WriteProcessMemory(DLL path) failed: " + formatLastErrorMessage(::GetLastError());
            }
            ::VirtualFreeEx(kProcessHandle, remotePathMemory, 0, MEM_RELEASE);
            ::CloseHandle(kProcessHandle);
            return false;
        }

        const HMODULE kKernel32Module = ::GetModuleHandleW(L"kernel32.dll");
        FARPROC loadLibraryAddress = kKernel32Module != nullptr
            ? ::GetProcAddress(kKernel32Module, "LoadLibraryW")
            : nullptr;
        if (loadLibraryAddress == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "GetProcAddress(LoadLibraryW) failed.";
            }
            ::VirtualFreeEx(kProcessHandle, remotePathMemory, 0, MEM_RELEASE);
            ::CloseHandle(kProcessHandle);
            return false;
        }

        HANDLE remoteThread = ::CreateRemoteThread(
            kProcessHandle,
            nullptr,
            0,
            reinterpret_cast<LPTHREAD_START_ROUTINE>(loadLibraryAddress),
            remotePathMemory,
            0,
            nullptr);
        if (remoteThread == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "CreateRemoteThread(LoadLibraryW) failed: " + formatLastErrorMessage(::GetLastError());
            }
            ::VirtualFreeEx(kProcessHandle, remotePathMemory, 0, MEM_RELEASE);
            ::CloseHandle(kProcessHandle);
            return false;
        }

        constexpr DWORD kLoadLibraryWaitTimeoutMs = 10000;
        const DWORD kWaitResult = ::WaitForSingleObject(remoteThread, kLoadLibraryWaitTimeoutMs);
        if (kWaitResult != WAIT_OBJECT_0)
        {
            const DWORD kWaitError = kWaitResult == WAIT_FAILED ? ::GetLastError() : ERROR_SUCCESS;
            const bool kCleanupScheduled = scheduleDeferredRemoteLoadLibraryCleanup(
                kProcessHandle,
                remoteThread,
                remotePathMemory);
            if (errorMessage != nullptr)
            {
                if (kCleanupScheduled)
                {
                    *errorMessage = "LoadLibraryW remote thread did not finish within "
                        + std::to_string(kLoadLibraryWaitTimeoutMs)
                        + " ms; deferred cleanup owns the remote path until the thread exits.";
                }
                else
                {
                    *errorMessage = "LoadLibraryW remote thread did not finish within "
                        + std::to_string(kLoadLibraryWaitTimeoutMs)
                        + " ms and deferred cleanup could not be scheduled; the remote DLL path was intentionally retained until the target process exits.";
                }
                if (kWaitResult == WAIT_FAILED)
                {
                    *errorMessage += " WaitForSingleObject failed: " + formatLastErrorMessage(kWaitError);
                }
            }

            if (!kCleanupScheduled)
            {
                // The remote thread may still read remotePathMemory; when thread creation fails, it is preferable to retain the small path memory block
                // in the target process rather than triggering VirtualFreeEx here, which would cause a dangling pointer for a remote LoadLibraryW call.
                ::CloseHandle(remoteThread);
                ::CloseHandle(kProcessHandle);
            }
            return false;
        }

        DWORD threadExitCode = 0;
        const BOOL kExitCodeOk = ::GetExitCodeThread(remoteThread, &threadExitCode);
        const DWORD kExitCodeError = kExitCodeOk == FALSE ? ::GetLastError() : ERROR_SUCCESS;
        ::CloseHandle(remoteThread);
        ::VirtualFreeEx(kProcessHandle, remotePathMemory, 0, MEM_RELEASE);
        ::CloseHandle(kProcessHandle);

        if (kExitCodeOk == FALSE)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "GetExitCodeThread(LoadLibraryW) failed: " + formatLastErrorMessage(kExitCodeError);
            }
            return false;
        }

        if (threadExitCode != 0)
        {
            return true;
        }

        if (errorMessage != nullptr)
        {
            *errorMessage = "LoadLibraryW returned NULL, DLL may not be loaded.";
        }
        return false;
    }

    bool injectShellcodeBuffer(
        const std::uint32_t pid,
        const std::vector<std::uint8_t>& shellcodeBuffer,
        std::string* const errorMessage)
    {
        if (shellcodeBuffer.empty())
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "Shellcode buffer is empty.";
            }
            return false;
        }

        const HANDLE kProcessHandle = ::OpenProcess(
            PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
            FALSE,
            toDwordPid(pid));
        if (kProcessHandle == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "OpenProcess(for shellcode inject) failed: " + formatLastErrorMessage(::GetLastError());
            }
            return false;
        }

        void* remoteMemory = ::VirtualAllocEx(
            kProcessHandle,
            nullptr,
            shellcodeBuffer.size(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE);
        if (remoteMemory == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "VirtualAllocEx(for shellcode) failed: " + formatLastErrorMessage(::GetLastError());
            }
            ::CloseHandle(kProcessHandle);
            return false;
        }

        SIZE_T bytesWritten = 0;
        if (::WriteProcessMemory(
            kProcessHandle,
            remoteMemory,
            shellcodeBuffer.data(),
            shellcodeBuffer.size(),
            &bytesWritten) == FALSE ||
            bytesWritten != shellcodeBuffer.size())
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "WriteProcessMemory(shellcode) failed: " + formatLastErrorMessage(::GetLastError());
            }
            ::VirtualFreeEx(kProcessHandle, remoteMemory, 0, MEM_RELEASE);
            ::CloseHandle(kProcessHandle);
            return false;
        }

        HANDLE remoteThread = ::CreateRemoteThread(
            kProcessHandle,
            nullptr,
            0,
            reinterpret_cast<LPTHREAD_START_ROUTINE>(remoteMemory),
            nullptr,
            0,
            nullptr);
        if (remoteThread == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "CreateRemoteThread(shellcode) failed: " + formatLastErrorMessage(::GetLastError());
            }
            ::VirtualFreeEx(kProcessHandle, remoteMemory, 0, MEM_RELEASE);
            ::CloseHandle(kProcessHandle);
            return false;
        }

        ::WaitForSingleObject(remoteThread, 2000);
        ::CloseHandle(remoteThread);
        ::CloseHandle(kProcessHandle);

        // To avoid exceptions caused by releasing memory while shellcode is still executing, do not actively release remoteMemory here.
        return true;
    }

    bool openFolderByPath(const std::string& targetPath, std::string* const errorMessage)
    {
        return openInExplorerByPath(targetPath, errorMessage);
    }

    bool queryTokenPrivilegesByProcessHandle(
        const HANDLE processHandle,
        std::vector<TokenPrivilegeInfo>* const privilegesOut,
        std::string* const errorMessage)
    {
        if (privilegesOut == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "QueryTokenPrivilegesByProcessHandle::privilegesOut cannot be null.";
            }
            return false;
        }
        privilegesOut->clear();

        if (processHandle == nullptr || processHandle == INVALID_HANDLE_VALUE)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "QueryTokenPrivilegesByProcessHandle::processHandle is invalid.";
            }
            return false;
        }

        HANDLE tokenHandle = nullptr;
        if (::OpenProcessToken(processHandle, TOKEN_QUERY, &tokenHandle) == FALSE
            || tokenHandle == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "OpenProcessToken(TOKEN_QUERY) failed: "
                    + formatLastErrorMessage(::GetLastError());
            }
            return false;
        }

        DWORD requiredSize = 0;
        ::SetLastError(ERROR_SUCCESS);
        const BOOL kSizeQueryOk = ::GetTokenInformation(
            tokenHandle,
            TokenPrivileges,
            nullptr,
            0,
            &requiredSize);
        const DWORD kSizeQueryError = ::GetLastError();
        const std::size_t kTokenPrivilegesHeaderSize =
            FIELD_OFFSET(TOKEN_PRIVILEGES, Privileges);
        if (kSizeQueryOk != FALSE
            || kSizeQueryError != ERROR_INSUFFICIENT_BUFFER
            || requiredSize < kTokenPrivilegesHeaderSize)
        {
            ::CloseHandle(tokenHandle);
            if (errorMessage != nullptr)
            {
                *errorMessage = "GetTokenInformation::TokenPrivileges size failed: "
                    + formatLastErrorMessage(kSizeQueryError);
            }
            return false;
        }

        const DWORD kBufferCapacity = requiredSize;
        std::vector<std::uint8_t> tokenBuffer(kBufferCapacity, 0);
        TOKEN_PRIVILEGES* const kTokenPrivileges = reinterpret_cast<TOKEN_PRIVILEGES*>(tokenBuffer.data());
        DWORD returnedSize = 0;
        if (::GetTokenInformation(
            tokenHandle,
            TokenPrivileges,
            kTokenPrivileges,
            kBufferCapacity,
            &returnedSize) == FALSE)
        {
            const DWORD kQueryError = ::GetLastError();
            ::CloseHandle(tokenHandle);
            if (errorMessage != nullptr)
            {
                *errorMessage = "GetTokenInformation::TokenPrivileges failed: "
                    + formatLastErrorMessage(kQueryError);
            }
            return false;
        }
        ::CloseHandle(tokenHandle);

        if (returnedSize < kTokenPrivilegesHeaderSize
            || returnedSize > kBufferCapacity)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "GetTokenInformation::TokenPrivileges returned an invalid size.";
            }
            return false;
        }
        const std::size_t kAvailablePrivilegeCount =
            (static_cast<std::size_t>(returnedSize) - kTokenPrivilegesHeaderSize)
            / sizeof(LUID_AND_ATTRIBUTES);
        if (static_cast<std::size_t>(kTokenPrivileges->PrivilegeCount)
            > kAvailablePrivilegeCount)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "GetTokenInformation::TokenPrivileges returned an invalid privilege count.";
            }
            return false;
        }

        std::vector<TokenPrivilegeLuidEntry> privilegeEntries;
        privilegeEntries.reserve(kTokenPrivileges->PrivilegeCount);
        for (DWORD privilegeIndex = 0; privilegeIndex < kTokenPrivileges->PrivilegeCount; ++privilegeIndex)
        {
            const LUID_AND_ATTRIBUTES& tokenPrivilege = kTokenPrivileges->Privileges[privilegeIndex];
            TokenPrivilegeLuidEntry privilegeEntry{};
            privilegeEntry.luidLowPart = tokenPrivilege.Luid.LowPart;
            privilegeEntry.luidHighPart = tokenPrivilege.Luid.HighPart;
            privilegeEntry.attributes = static_cast<std::uint32_t>(tokenPrivilege.Attributes);
            privilegeEntries.push_back(privilegeEntry);
        }

        return buildKnownTokenPrivilegeSnapshot(
            privilegeEntries,
            privilegesOut,
            errorMessage);
    }

    bool queryTokenPrivilegesByPid(
        const std::uint32_t sourcePid,
        std::vector<TokenPrivilegeInfo>* const privilegesOut,
        std::string* const errorMessage)
    {
        if (sourcePid == 0U)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "QueryTokenPrivilegesByPid::sourcePid cannot be 0.";
            }
            return false;
        }

        const HANDLE kProcessHandle = ::OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION,
            FALSE,
            toDwordPid(sourcePid));
        if (kProcessHandle == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "OpenProcess(for token query) failed: "
                    + formatLastErrorMessage(::GetLastError());
            }
            return false;
        }

        const bool kQueryOk = queryTokenPrivilegesByProcessHandle(
            kProcessHandle,
            privilegesOut,
            errorMessage);
        ::CloseHandle(kProcessHandle);
        return kQueryOk;
    }

    bool buildKnownTokenPrivilegeSnapshot(
        const std::vector<TokenPrivilegeLuidEntry>& entries,
        std::vector<TokenPrivilegeInfo>* const privilegesOut,
        std::string* const errorMessage)
    {
        if (privilegesOut == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "QueryTokenPrivilegesByPid::privilegesOut cannot be null.";
            }
            return false;
        }

        privilegesOut->clear();
        privilegesOut->reserve(knownTokenPrivilegeNames().size());
        for (const std::string& privilegeName : knownTokenPrivilegeNames())
        {
            TokenPrivilegeInfo privilegeInfo{};
            privilegeInfo.privilegeName = privilegeName;

            const std::wstring kPrivilegeNameWide = ks::str::utf8ToUtf16(privilegeName);
            LUID privilegeLuid{};
            if (kPrivilegeNameWide.empty()
                || ::LookupPrivilegeValueW(nullptr, kPrivilegeNameWide.c_str(), &privilegeLuid) == FALSE)
            {
                privilegesOut->push_back(std::move(privilegeInfo));
                continue;
            }

            privilegeInfo.luidLowPart = privilegeLuid.LowPart;
            privilegeInfo.luidHighPart = privilegeLuid.HighPart;
            privilegeInfo.luidKnown = true;
            privilegeInfo.state = TokenPrivilegeState::kNotPresent;
            for (const TokenPrivilegeLuidEntry& tokenPrivilege : entries)
            {
                if (tokenPrivilege.luidLowPart != privilegeLuid.LowPart
                    || tokenPrivilege.luidHighPart != privilegeLuid.HighPart)
                {
                    continue;
                }

                privilegeInfo.attributes = tokenPrivilege.attributes;
                privilegeInfo.state = (tokenPrivilege.attributes & SE_PRIVILEGE_ENABLED) != 0
                    ? TokenPrivilegeState::kEnabled
                    : TokenPrivilegeState::kDisabled;
                break;
            }
            privilegesOut->push_back(std::move(privilegeInfo));
        }

        if (errorMessage != nullptr)
        {
            errorMessage->clear();
        }
        return true;
    }

    bool applyTokenPrivilegeEditsByProcessHandle(
        const HANDLE processHandle,
        const std::uint32_t tokenDesiredAccess,
        const bool duplicatePrimaryToken,
        const std::vector<TokenPrivilegeEdit>& edits,
        std::string* const errorMessage)
    {
        const DWORD kDesiredAccess = tokenDesiredAccess == 0
            ? kDefaultTokenDesiredAccess
            : static_cast<DWORD>(tokenDesiredAccess);

        if (processHandle == nullptr || processHandle == INVALID_HANDLE_VALUE)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "ApplyTokenPrivilegeEditsByProcessHandle::processHandle is invalid.";
            }
            return false;
        }

        HANDLE sourceToken = nullptr;
        if (::OpenProcessToken(processHandle, kDesiredAccess, &sourceToken) == FALSE
            || sourceToken == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "OpenProcessToken(for adjustment) failed: "
                    + formatLastErrorMessage(::GetLastError());
            }
            return false;
        }

        HANDLE workingToken = sourceToken;
        HANDLE duplicatedToken = nullptr;
        if (duplicatePrimaryToken)
        {
            if (!duplicatePrimaryTokenHandle(sourceToken, kDesiredAccess, duplicatedToken, errorMessage))
            {
                ::CloseHandle(sourceToken);
                return false;
            }
            workingToken = duplicatedToken;
        }

        const bool kAdjustOk = applyPrivilegeEdits(workingToken, edits, errorMessage);

        if (duplicatedToken != nullptr)
        {
            ::CloseHandle(duplicatedToken);
        }
        if (sourceToken != nullptr)
        {
            ::CloseHandle(sourceToken);
        }
        if (kAdjustOk && errorMessage != nullptr)
        {
            std::ostringstream stream;
            stream << "AdjustTokenPrivileges succeeded, edited privileges=" << edits.size();
            *errorMessage = stream.str();
        }
        return kAdjustOk;
    }

    bool applyTokenPrivilegeEditsByPid(
        const std::uint32_t sourcePid,
        const std::uint32_t tokenDesiredAccess,
        const bool duplicatePrimaryToken,
        const std::vector<TokenPrivilegeEdit>& edits,
        std::string* const errorMessage)
    {
        if (sourcePid == 0U)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "ApplyTokenPrivilegeEditsByPid::sourcePid cannot be 0.";
            }
            return false;
        }

        const HANDLE kProcessHandle = ::OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION,
            FALSE,
            toDwordPid(sourcePid));
        if (kProcessHandle == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "OpenProcess(for token adjustment) failed: "
                    + formatLastErrorMessage(::GetLastError());
            }
            return false;
        }

        const bool kAdjustOk = applyTokenPrivilegeEditsByProcessHandle(
            kProcessHandle,
            tokenDesiredAccess,
            duplicatePrimaryToken,
            edits,
            errorMessage);
        ::CloseHandle(kProcessHandle);
        return kAdjustOk;
    }

    bool launchProcess(
        const CreateProcessRequest& request,
        CreateProcessResult* const resultOut)
    {
        CreateProcessResult localResult{};
        localResult.usedTokenPath = request.tokenModeEnabled;

        std::wstring applicationNameWide;
        LPCWSTR applicationNamePtr = nullptr;
        if (request.useApplicationName)
        {
            applicationNameWide = ks::str::utf8ToUtf16(request.applicationName);
            applicationNamePtr = applicationNameWide.empty() ? nullptr : applicationNameWide.c_str();
        }

        std::wstring commandLineWide;
        std::vector<wchar_t> commandLineBuffer;
        LPWSTR commandLinePtr = nullptr;
        if (request.useCommandLine)
        {
            commandLineWide = ks::str::utf8ToUtf16(request.commandLine);
            commandLineBuffer.assign(commandLineWide.begin(), commandLineWide.end());
            commandLineBuffer.push_back(L'\0');
            commandLinePtr = commandLineBuffer.data();
        }

        SECURITY_ATTRIBUTES processSecurityAttributes{};
        SECURITY_ATTRIBUTES threadSecurityAttributes{};
        SECURITY_ATTRIBUTES* processSecurityPtr = buildSecurityAttributes(
            request.processAttributes,
            processSecurityAttributes) ? &processSecurityAttributes : nullptr;
        SECURITY_ATTRIBUTES* threadSecurityPtr = buildSecurityAttributes(
            request.threadAttributes,
            threadSecurityAttributes) ? &threadSecurityAttributes : nullptr;

        std::vector<wchar_t> unicodeEnvironmentBlock;
        std::vector<char> ansiEnvironmentBlock;
        LPVOID environmentPtr = nullptr;
        DWORD creationFlags = static_cast<DWORD>(request.creationFlags);
        if (request.useEnvironment)
        {
            const bool kUseUnicodeEnvironment =
                request.environmentUnicode || ((creationFlags & CREATE_UNICODE_ENVIRONMENT) != 0);
            if (kUseUnicodeEnvironment)
            {
                creationFlags |= CREATE_UNICODE_ENVIRONMENT;
                unicodeEnvironmentBlock = buildUnicodeEnvironmentBlock(request.environmentEntries);
                environmentPtr = unicodeEnvironmentBlock.empty() ? nullptr : unicodeEnvironmentBlock.data();
            }
            else
            {
                creationFlags &= ~static_cast<DWORD>(CREATE_UNICODE_ENVIRONMENT);
                ansiEnvironmentBlock = buildAnsiEnvironmentBlock(request.environmentEntries);
                environmentPtr = ansiEnvironmentBlock.empty() ? nullptr : ansiEnvironmentBlock.data();
            }
        }

        std::wstring currentDirectoryWide;
        LPCWSTR currentDirectoryPtr = nullptr;
        if (request.useCurrentDirectory)
        {
            currentDirectoryWide = ks::str::utf8ToUtf16(request.currentDirectory);
            currentDirectoryPtr = currentDirectoryWide.empty() ? nullptr : currentDirectoryWide.c_str();
        }

        STARTUPINFOW startupInfo{};
        StartupInfoBufferSet startupBufferSet{};
        buildStartupInfo(
            request.startupInfo,
            startupInfo,
            startupBufferSet);
        STARTUPINFOW* const kStartupInfoPtr = &startupInfo;

        PROCESS_INFORMATION processInfo{};
        initializeProcessInformationOutput(processInfo);
        PROCESS_INFORMATION* const kProcessInfoPtr = &processInfo;

        auto finalizeSuccess = [&localResult, kProcessInfoPtr]() {
            localResult.success = true;
            if (kProcessInfoPtr == nullptr)
            {
                return;
            }

            localResult.processInfoAvailable = true;
            localResult.hProcess = handleToUint64(kProcessInfoPtr->hProcess);
            localResult.hThread = handleToUint64(kProcessInfoPtr->hThread);
            localResult.dwProcessId = static_cast<std::uint32_t>(kProcessInfoPtr->dwProcessId);
            localResult.dwThreadId = static_cast<std::uint32_t>(kProcessInfoPtr->dwThreadId);

            if (kProcessInfoPtr->hThread != nullptr)
            {
                ::CloseHandle(kProcessInfoPtr->hThread);
                kProcessInfoPtr->hThread = nullptr;
            }
            if (kProcessInfoPtr->hProcess != nullptr)
            {
                ::CloseHandle(kProcessInfoPtr->hProcess);
                kProcessInfoPtr->hProcess = nullptr;
            }
        };

        if (!request.tokenModeEnabled)
        {
            const BOOL kCreateOk = ::CreateProcessW(
                applicationNamePtr,
                commandLinePtr,
                processSecurityPtr,
                threadSecurityPtr,
                request.inheritHandles ? TRUE : FALSE,
                creationFlags,
                environmentPtr,
                currentDirectoryPtr,
                kStartupInfoPtr,
                kProcessInfoPtr);

            if (kCreateOk == FALSE)
            {
                localResult.win32Error = static_cast<std::uint32_t>(::GetLastError());
                localResult.detailText = "CreateProcessW failed: " + formatLastErrorMessage(localResult.win32Error);
                if (resultOut != nullptr)
                {
                    *resultOut = localResult;
                }
                return false;
            }

            localResult.detailText = "CreateProcessW succeeded.";
            finalizeSuccess();
            if (resultOut != nullptr)
            {
                *resultOut = localResult;
            }
            return true;
        }

        const DWORD kDesiredAccess = request.tokenDesiredAccess == 0
            ? kDefaultTokenDesiredAccess
            : static_cast<DWORD>(request.tokenDesiredAccess);
        HANDLE sourceToken = nullptr;
        std::string tokenError;
        if (!openTokenByProcessPid(request.tokenSourcePid, kDesiredAccess, sourceToken, &tokenError))
        {
            localResult.win32Error = static_cast<std::uint32_t>(::GetLastError());
            localResult.detailText = tokenError;
            if (resultOut != nullptr)
            {
                *resultOut = localResult;
            }
            return false;
        }

        HANDLE workingToken = sourceToken;
        HANDLE duplicatedPrimaryToken = nullptr;
        if (request.duplicatePrimaryToken)
        {
            if (!duplicatePrimaryTokenHandle(sourceToken, kDesiredAccess, duplicatedPrimaryToken, &tokenError))
            {
                ::CloseHandle(sourceToken);
                localResult.win32Error = static_cast<std::uint32_t>(::GetLastError());
                localResult.detailText = tokenError;
                if (resultOut != nullptr)
                {
                    *resultOut = localResult;
                }
                return false;
            }
            workingToken = duplicatedPrimaryToken;
        }

        if (!applyPrivilegeEdits(workingToken, request.tokenPrivilegeEdits, &tokenError))
        {
            if (duplicatedPrimaryToken != nullptr)
            {
                ::CloseHandle(duplicatedPrimaryToken);
            }
            ::CloseHandle(sourceToken);
            localResult.win32Error = static_cast<std::uint32_t>(::GetLastError());
            localResult.detailText = tokenError;
            if (resultOut != nullptr)
            {
                *resultOut = localResult;
            }
            return false;
        }

        const BOOL kCreateAsUserOk = ::CreateProcessAsUserW(
            workingToken,
            applicationNamePtr,
            commandLinePtr,
            processSecurityPtr,
            threadSecurityPtr,
            request.inheritHandles ? TRUE : FALSE,
            creationFlags,
            environmentPtr,
            currentDirectoryPtr,
            kStartupInfoPtr,
            kProcessInfoPtr);
        if (kCreateAsUserOk != FALSE)
        {
            localResult.detailText = "CreateProcessAsUserW succeeded.";
            finalizeSuccess();
            if (duplicatedPrimaryToken != nullptr)
            {
                ::CloseHandle(duplicatedPrimaryToken);
            }
            ::CloseHandle(sourceToken);
            if (resultOut != nullptr)
            {
                *resultOut = localResult;
            }
            return true;
        }

        const DWORD kCreateAsUserError = ::GetLastError();
        // Compatibility fallback: attempt CreateProcessWithTokenW when SeAssignPrimaryTokenPrivilege is missing in some environments.
        const BOOL kCreateWithTokenOk = ::CreateProcessWithTokenW(
            workingToken,
            LOGON_WITH_PROFILE,
            applicationNamePtr,
            commandLinePtr,
            creationFlags,
            environmentPtr,
            currentDirectoryPtr,
            kStartupInfoPtr,
            kProcessInfoPtr);
        if (kCreateWithTokenOk != FALSE)
        {
            localResult.usedCreateProcessWithTokenFallback = true;
            localResult.detailText = "CreateProcessAsUserW failed, fallback CreateProcessWithTokenW succeeded.";
            finalizeSuccess();
            if (duplicatedPrimaryToken != nullptr)
            {
                ::CloseHandle(duplicatedPrimaryToken);
            }
            ::CloseHandle(sourceToken);
            if (resultOut != nullptr)
            {
                *resultOut = localResult;
            }
            return true;
        }

        const DWORD kFallbackError = ::GetLastError();
        std::ostringstream detailStream;
        detailStream
            << "CreateProcessAsUserW failed: " << formatLastErrorMessage(kCreateAsUserError)
            << " | CreateProcessWithTokenW fallback failed: " << formatLastErrorMessage(kFallbackError);
        localResult.win32Error = static_cast<std::uint32_t>(kFallbackError);
        localResult.detailText = detailStream.str();

        if (duplicatedPrimaryToken != nullptr)
        {
            ::CloseHandle(duplicatedPrimaryToken);
        }
        ::CloseHandle(sourceToken);
        if (resultOut != nullptr)
        {
            *resultOut = localResult;
        }
        return false;
    }

    bool launchSuspendedProcess(
        const SuspendedProcessLaunchRequest& request,
        SuspendedProcessLaunchResult* const resultOut)
    {
        if (resultOut == nullptr)
        {
            return false;
        }

        SuspendedProcessLaunchResult localResult{};
        const auto kFinish = [&localResult, resultOut](const bool success) {
            localResult.success = success;
            *resultOut = localResult;
            return success;
        };

        const std::wstring kImagePathWide = ks::str::utf8ToUtf16(request.imagePath);
        if (kImagePathWide.empty())
        {
            localResult.failure = SuspendedProcessLaunchFailure::kInvalidArgument;
            localResult.detailText = "Target image path is empty or cannot be converted to UTF-16.";
            return kFinish(false);
        }

        // quoteCommandLineArgument: Responsible only for Windows backslash/quote rules for argv[0].
        // Append user-provided parameter text as-is to avoid altering its existing command-line semantics.
        const auto kQuoteCommandLineArgument = [](const std::wstring& argumentText) {
            std::wstring quotedText;
            quotedText.reserve(argumentText.size() + 2);
            quotedText.push_back(L'\"');

            std::size_t slashCount = 0;
            for (const wchar_t kCharacterValue : argumentText)
            {
                if (kCharacterValue == L'\\')
                {
                    ++slashCount;
                    continue;
                }

                if (kCharacterValue == L'\"')
                {
                    quotedText.append(slashCount * 2 + 1, L'\\');
                    quotedText.push_back(L'\"');
                    slashCount = 0;
                    continue;
                }

                if (slashCount > 0)
                {
                    quotedText.append(slashCount, L'\\');
                    slashCount = 0;
                }
                quotedText.push_back(kCharacterValue);
            }

            if (slashCount > 0)
            {
                quotedText.append(slashCount * 2, L'\\');
            }
            quotedText.push_back(L'\"');
            return quotedText;
        };

        std::wstring commandLineWide = kQuoteCommandLineArgument(kImagePathWide);
        if (!request.argumentText.empty())
        {
            commandLineWide.push_back(L' ');
            commandLineWide += ks::str::utf8ToUtf16(request.argumentText);
        }

        std::wstring workingDirectoryWide;
        LPCWSTR workingDirectoryPointer = nullptr;
        if (!request.workingDirectory.empty())
        {
            workingDirectoryWide = ks::str::utf8ToUtf16(request.workingDirectory);
            if (!workingDirectoryWide.empty())
            {
                workingDirectoryPointer = workingDirectoryWide.c_str();
            }
        }

        HANDLE currentTokenHandle = nullptr;
        bool currentProcessElevated = false;
        if (::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &currentTokenHandle) == FALSE)
        {
            localResult.failure = SuspendedProcessLaunchFailure::kCreateFailed;
            localResult.win32Error = static_cast<std::uint32_t>(::GetLastError());
            localResult.detailText = "OpenProcessToken(current process) failed: "
                + formatLastErrorMessage(localResult.win32Error);
            return kFinish(false);
        }

        TOKEN_ELEVATION tokenElevation{};
        DWORD returnedLength = 0;
        const BOOL kElevationQueryOk = ::GetTokenInformation(
            currentTokenHandle,
            TokenElevation,
            &tokenElevation,
            sizeof(tokenElevation),
            &returnedLength);
        const DWORD kElevationQueryError = kElevationQueryOk == FALSE ? ::GetLastError() : ERROR_SUCCESS;
        if (kElevationQueryOk == FALSE)
        {
            ::CloseHandle(currentTokenHandle);
            localResult.failure = SuspendedProcessLaunchFailure::kCreateFailed;
            localResult.win32Error = static_cast<std::uint32_t>(kElevationQueryError);
            localResult.detailText = "GetTokenInformation(TokenElevation) failed: "
                + formatLastErrorMessage(kElevationQueryError);
            return kFinish(false);
        }
        currentProcessElevated = kElevationQueryOk != FALSE && tokenElevation.TokenIsElevated != 0;

        if (request.runAsAdministrator && !currentProcessElevated)
        {
            ::CloseHandle(currentTokenHandle);
            localResult.failure = SuspendedProcessLaunchFailure::kAdministratorRequired;
            localResult.win32Error = static_cast<std::uint32_t>(
                kElevationQueryOk != FALSE ? ERROR_ELEVATION_REQUIRED : kElevationQueryError);
            localResult.detailText = kElevationQueryOk != FALSE
                ? "Current KSword process is not elevated."
                : "GetTokenInformation(TokenElevation) failed: " + formatLastErrorMessage(kElevationQueryError);
            return kFinish(false);
        }

        HANDLE unelevatedPrimaryTokenHandle = nullptr;
        std::string unelevatedTokenError;
        if (currentProcessElevated && !request.runAsAdministrator && !request.allowElevatedFallback)
        {
            TOKEN_LINKED_TOKEN linkedTokenInfo{};
            returnedLength = 0;
            const BOOL kLinkedTokenQueryOk = ::GetTokenInformation(
                currentTokenHandle,
                TokenLinkedToken,
                &linkedTokenInfo,
                sizeof(linkedTokenInfo),
                &returnedLength);
            if (kLinkedTokenQueryOk == FALSE || linkedTokenInfo.LinkedToken == nullptr)
            {
                const DWORD kLinkedTokenError = ::GetLastError();
                unelevatedTokenError = "GetTokenInformation(TokenLinkedToken) failed: "
                    + formatLastErrorMessage(kLinkedTokenError);
            }
            else
            {
                const DWORD kPrimaryTokenAccess = TOKEN_ASSIGN_PRIMARY
                    | TOKEN_DUPLICATE
                    | TOKEN_QUERY
                    | TOKEN_ADJUST_DEFAULT
                    | TOKEN_ADJUST_SESSIONID
                    | TOKEN_IMPERSONATE;
                if (::DuplicateTokenEx(
                    linkedTokenInfo.LinkedToken,
                    kPrimaryTokenAccess,
                    nullptr,
                    SecurityImpersonation,
                    TokenPrimary,
                    &unelevatedPrimaryTokenHandle) == FALSE
                    || unelevatedPrimaryTokenHandle == nullptr)
                {
                    const DWORD kDuplicateError = ::GetLastError();
                    unelevatedTokenError = "DuplicateTokenEx(TokenLinkedToken) failed: "
                        + formatLastErrorMessage(kDuplicateError);
                }
                ::CloseHandle(linkedTokenInfo.LinkedToken);
            }

            if (unelevatedPrimaryTokenHandle == nullptr)
            {
                ::CloseHandle(currentTokenHandle);
                localResult.failure = SuspendedProcessLaunchFailure::kUnelevatedTokenUnavailable;
                localResult.detailText = unelevatedTokenError.empty()
                    ? "No unelevated linked token is available."
                    : unelevatedTokenError;
                return kFinish(false);
            }
        }
        ::CloseHandle(currentTokenHandle);

        const auto kInitializeProcessInformation = []() {
            PROCESS_INFORMATION processInformation{};
            return processInformation;
        };
        const auto kFinalizeSuccess = [&localResult](PROCESS_INFORMATION& processInformation) {
            localResult.processId = static_cast<std::uint32_t>(processInformation.dwProcessId);
            localResult.threadId = static_cast<std::uint32_t>(processInformation.dwThreadId);
            localResult.processHandle = reinterpret_cast<std::uint64_t>(processInformation.hProcess);
            localResult.initialThreadHandle = reinterpret_cast<std::uint64_t>(processInformation.hThread);
            processInformation.hProcess = nullptr;
            processInformation.hThread = nullptr;
        };
        const auto kBuildMutableCommandLine = [&commandLineWide]() {
            std::vector<wchar_t> commandLineBuffer(commandLineWide.begin(), commandLineWide.end());
            commandLineBuffer.push_back(L'\0');
            return commandLineBuffer;
        };

        STARTUPINFOW startupInfo{};
        startupInfo.cb = sizeof(startupInfo);
        const DWORD kCreationFlags = CREATE_SUSPENDED;

        if (unelevatedPrimaryTokenHandle == nullptr)
        {
            PROCESS_INFORMATION processInformation = kInitializeProcessInformation();
            std::vector<wchar_t> commandLineBuffer = kBuildMutableCommandLine();
            const BOOL kCreateOk = ::CreateProcessW(
                kImagePathWide.c_str(),
                commandLineBuffer.data(),
                nullptr,
                nullptr,
                FALSE,
                kCreationFlags,
                nullptr,
                workingDirectoryPointer,
                &startupInfo,
                &processInformation);
            if (kCreateOk == FALSE)
            {
                localResult.failure = SuspendedProcessLaunchFailure::kCreateFailed;
                localResult.win32Error = static_cast<std::uint32_t>(::GetLastError());
                localResult.detailText = "CreateProcessW(CREATE_SUSPENDED) failed: "
                    + formatLastErrorMessage(localResult.win32Error);
                return kFinish(false);
            }

            localResult.usedElevatedFallback = currentProcessElevated
                && !request.runAsAdministrator
                && request.allowElevatedFallback;
            localResult.detailText = "CreateProcessW(CREATE_SUSPENDED) succeeded.";
            kFinalizeSuccess(processInformation);
            return kFinish(true);
        }

        PROCESS_INFORMATION processInformation = kInitializeProcessInformation();
        std::vector<wchar_t> commandLineBuffer = kBuildMutableCommandLine();
        BOOL createOk = ::CreateProcessAsUserW(
            unelevatedPrimaryTokenHandle,
            kImagePathWide.c_str(),
            commandLineBuffer.data(),
            nullptr,
            nullptr,
            FALSE,
            kCreationFlags,
            nullptr,
            workingDirectoryPointer,
            &startupInfo,
            &processInformation);
        if (createOk == FALSE)
        {
            const DWORD kCreateAsUserError = ::GetLastError();
            processInformation = kInitializeProcessInformation();
            commandLineBuffer = kBuildMutableCommandLine();
            createOk = ::CreateProcessWithTokenW(
                unelevatedPrimaryTokenHandle,
                LOGON_WITH_PROFILE,
                kImagePathWide.c_str(),
                commandLineBuffer.data(),
                kCreationFlags,
                nullptr,
                workingDirectoryPointer,
                &startupInfo,
                &processInformation);
            if (createOk == FALSE)
            {
                const DWORD kCreateWithTokenError = ::GetLastError();
                ::CloseHandle(unelevatedPrimaryTokenHandle);
                localResult.failure = SuspendedProcessLaunchFailure::kUnelevatedTokenUnavailable;
                localResult.win32Error = static_cast<std::uint32_t>(kCreateWithTokenError);
                localResult.detailText = "CreateProcessAsUserW(TokenLinkedToken) failed: "
                    + formatLastErrorMessage(kCreateAsUserError)
                    + " | CreateProcessWithTokenW fallback failed: "
                    + formatLastErrorMessage(kCreateWithTokenError);
                return kFinish(false);
            }
            localResult.detailText = "CreateProcessAsUserW(TokenLinkedToken) failed; CreateProcessWithTokenW(CREATE_SUSPENDED) succeeded.";
        }
        else
        {
            localResult.detailText = "CreateProcessAsUserW(TokenLinkedToken, CREATE_SUSPENDED) succeeded.";
        }

        ::CloseHandle(unelevatedPrimaryTokenHandle);
        localResult.usedUnelevatedToken = true;
        kFinalizeSuccess(processInformation);
        return kFinish(true);
    }

    bool resumeSuspendedProcessInitialThread(
        const std::uint64_t initialThreadHandle,
        std::string* const errorMessage)
    {
        const HANDLE kThreadHandle = reinterpret_cast<HANDLE>(initialThreadHandle);
        if (kThreadHandle == nullptr || kThreadHandle == INVALID_HANDLE_VALUE)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "Initial thread handle is invalid.";
            }
            return false;
        }

        if (::ResumeThread(kThreadHandle) == static_cast<DWORD>(-1))
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "ResumeThread failed: " + formatLastErrorMessage(::GetLastError());
            }
            return false;
        }
        return true;
    }

    bool terminateSuspendedProcessByHandle(
        const std::uint64_t processHandle,
        std::string* const errorMessage)
    {
        const HANDLE kNativeProcessHandle = reinterpret_cast<HANDLE>(processHandle);
        if (kNativeProcessHandle == nullptr || kNativeProcessHandle == INVALID_HANDLE_VALUE)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "Suspended process handle is invalid.";
            }
            return false;
        }

        const BOOL kTerminateOk = ::TerminateProcess(kNativeProcessHandle, 1);
        const DWORD kTerminateError = kTerminateOk != FALSE ? ERROR_SUCCESS : ::GetLastError();
        if (kTerminateOk != FALSE)
        {
            return true;
        }

        if (errorMessage != nullptr)
        {
            *errorMessage = "TerminateProcess failed: " + formatLastErrorMessage(kTerminateError);
        }
        return false;
    }

    void closeSuspendedProcessInitialThreadHandle(const std::uint64_t initialThreadHandle)
    {
        const HANDLE kThreadHandle = reinterpret_cast<HANDLE>(initialThreadHandle);
        if (kThreadHandle != nullptr && kThreadHandle != INVALID_HANDLE_VALUE)
        {
            ::CloseHandle(kThreadHandle);
        }
    }

    void closeSuspendedProcessHandle(const std::uint64_t processHandle)
    {
        const HANDLE kNativeProcessHandle = reinterpret_cast<HANDLE>(processHandle);
        if (kNativeProcessHandle != nullptr && kNativeProcessHandle != INVALID_HANDLE_VALUE)
        {
            ::CloseHandle(kNativeProcessHandle);
        }
    }

    std::wstring getCurrentProcessPath()
    {
        wchar_t szPath[MAX_PATH] = { 0 };
        if (GetModuleFileNameW(NULL, szPath, MAX_PATH) == 0)
        {
            return L"";
        }
        return std::wstring(szPath);
    }
}

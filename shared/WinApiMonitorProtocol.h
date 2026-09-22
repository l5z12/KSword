#pragma once

// ============================================================
// shared/WinApiMonitorProtocol.h
// Purpose:
// 1) Define protocol constants shared between the Ksword main program and the APIMonitor_x64 DLL;
// 2) Unify naming conventions for named pipes, configuration files, and stop marker files;
// 3) Define fixed-length event packets to prevent drift in structure layout between UI and Agent.
// ============================================================

#include <cstdint>
#include <iterator>
#include <string>
#include <type_traits>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>

namespace ks::winapi_monitor
{
    // kProtocolVersion：
    // - Purpose: Protocol version number.
    // - Usage: Both the UI and Agent can use this when sending/receiving event packets for quick structure compatibility verification.
    inline constexpr std::uint32_t kProtocolVersion = 0x20260405U;

    // kMaxModuleNameChars / kMaxApiNameChars / kMaxDetailChars：
    // - Purpose: Define fixed-length wide-character buffer sizes.
    // - Note: Fixed lengths are used to facilitate direct transmission of the entire structure over named pipes.
    inline constexpr std::size_t kMaxModuleNameChars = 32;
    inline constexpr std::size_t kMaxApiNameChars = 64;
    inline constexpr std::size_t kMaxDetailChars = 320;

    // kDefaultRawHookModules：
    // - Inputs: None;
    // - Handling: serves as the default module directory for Raw Fallback shared between UI and Agent, covering common Win32, network, COM, encryption, and service-related DLLs;
    //   ntdll's syscall/CRT-adjacent exports are unsuitable for generic Raw hooks; they are instead covered by the strongly typed Nt* table and precise Fake Success rules.
    // - Returns: a semicolon-delimited string of module names, to be split into an editable list by the caller as needed.
    inline constexpr const wchar_t* kDefaultRawHookModules =
        L"KernelBase.dll;kernel32.dll;advapi32.dll;user32.dll;gdi32.dll;gdi32full.dll;"
        L"ws2_32.dll;wininet.dll;winhttp.dll;iphlpapi.dll;dnsapi.dll;netapi32.dll;secur32.dll;"
        L"rpcrt4.dll;ole32.dll;oleaut32.dll;combase.dll;shell32.dll;shlwapi.dll;crypt32.dll;"
        L"bcrypt.dll;ncrypt.dll;wintrust.dll;urlmon.dll;psapi.dll;wtsapi32.dll;version.dll;"
        L"userenv.dll;profapi.dll;samcli.dll;wldap32.dll;setupapi.dll;cfgmgr32.dll;wevtapi.dll;tdh.dll";

    // kDefaultRawHookDenyList：
    // - Inputs: None;
    // - Processing: Raw Fallback default exclude list covers high-frequency/basic runtime/synchronization/loader/memory/string APIs, supporting exact or prefix* matching.
    // - Returns: a semicolon-separated list of function names or wildcard prefixes; strongly typed Hooks are unaffected by this blacklist.
    // - Note: This list is the 'built-in default denylist', controlled separately by raw_use_default_denylist; raw_denylist carries only user-added rules.
    inline constexpr const wchar_t* kDefaultRawHookDenyList =
        L"Rtl*;Ldr*;memcpy;memmove;memset;memcmp;memchr;CopyMemory;MoveMemory;ZeroMemory;FillMemory;SecureZeroMemory;"
        L"str*;_str*;wcs*;_wcs*;mbs*;_mbs*;lstr*;strlen;strcmp;strncmp;sprintf*;swprintf*;vsprintf*;vswprintf*;"
        L"StringCch*;StringCb*;RtlAllocateHeap;RtlFreeHeap;RtlReAllocateHeap;HeapAlloc;HeapFree;HeapReAlloc;HeapSize;"
        L"HeapValidate;HeapCompact;HeapWalk;GetProcessHeap;GetProcessHeaps;LocalAlloc;LocalFree;LocalReAlloc;"
        L"GlobalAlloc;GlobalFree;GlobalReAlloc;malloc;free;calloc;realloc;GetLastError;SetLastError;RtlGetLastWin32Error;"
        L"RtlSetLastWin32Error;EnterCriticalSection;LeaveCriticalSection;TryEnterCriticalSection;"
        L"InitializeCriticalSection*;DeleteCriticalSection;AcquireSRWLock*;ReleaseSRWLock*;"
        L"Nt*;Zw*;WaitForSingleObject;WaitForSingleObjectEx;WaitForMultipleObjects;WaitForMultipleObjectsEx;"
        L"WaitOnAddress;WakeByAddress*;Sleep;SleepEx;"
        L"QueryPerformanceCounter;QueryPerformanceFrequency;"
        L"GetTickCount;GetTickCount64;GetSystemTime*;GetLocalTime;GetTimeZoneInformation*;"
        L"TlsGetValue;TlsSetValue;FlsGetValue;FlsSetValue;Interlocked*;GetCurrentProcess*;GetCurrentThread*;"
        L"GetModuleHandle*;GetModuleFileName*;CloseHandle;EncodePointer;DecodePointer;IsBad*;"
        L"GetProcAddress;LoadLibrary*;FreeLibrary";

    // EventCategory：
    // - Purpose: Uniformly mark the major category to which an API event belongs.
    // - Invocation: UI renders colors, filters, and statistics based on category.
    enum class EventCategory : std::uint32_t
    {
        kUnknown = 0,
        kFile = 1,
        kRegistry = 2,
        kNetwork = 3,
        kProcess = 4,
        kLoader = 5,
        kInternal = 6
    };

    // ApiMonitorEventPacket：
    // - Purpose: Fixed-length event packet transmitted over a named pipe;
    // - Invocation: The Agent fills the packet and writes it as a whole via WriteFile; the UI reads the whole packet via ReadFile and parses it directly.
    struct ApiMonitorEventPacket
    {
        std::uint32_t size = sizeof(ApiMonitorEventPacket);     // size: current structure size.
        std::uint32_t version = kProtocolVersion;               // version: protocol version number.
        std::uint32_t pid = 0;                                  // pid: Process ID triggering the API.
        std::uint32_t tid = 0;                                  // tid: thread ID that triggered the API.
        std::uint64_t timestamp100ns = 0;                       // timestamp100ns: FILETIME base timestamp.
        std::uint32_t category = 0;                             // category: EventCategory value.
        std::int32_t resultCode = 0;                            // resultCode: Win32/LSTATUS/WSA error code.
        wchar_t moduleName[kMaxModuleNameChars] = {};           // moduleName: Name of the module owning the API.
        wchar_t apiName[kMaxApiNameChars] = {};                 // apiName: API name.
        wchar_t detailText[kMaxDetailChars] = {};               // detailText: Compressed detail text.
    };

    static_assert(
        std::is_trivially_copyable_v<ApiMonitorEventPacket>,
        "ApiMonitorEventPacket 必须可平凡复制，便于直接通过管道收发。");

    // trimTrailingSlash：
    // - Purpose: Remove trailing '\' or '/' characters from the end of a directory path.
    // - Call: normalize paths before concatenating session directory and configuration file paths.
    inline std::wstring trimTrailingSlash(const std::wstring& pathText)
    {
        std::wstring normalizedText = pathText;
        while (!normalizedText.empty())
        {
            const wchar_t kLastChar = normalizedText.back();
            if (kLastChar != L'\\' && kLastChar != L'/')
            {
                break;
            }
            normalizedText.pop_back();
        }
        return normalizedText;
    }

    // joinPath：
    // - Purpose: Concatenate directory and file names using Windows-style paths;
    // - Call: Constructs the session directory, INI path, and stop marker file path.
    inline std::wstring joinPath(const std::wstring& leftPath, const std::wstring& rightPath)
    {
        if (leftPath.empty())
        {
            return rightPath;
        }

        const std::wstring kNormalizedLeft = trimTrailingSlash(leftPath);
        if (kNormalizedLeft.empty())
        {
            return rightPath;
        }
        return kNormalizedLeft + L"\\" + rightPath;
    }

    // queryTempDirectory：
    // - Purpose: Returns the current user's temporary directory.
    // - Usage: Reused when UI writes configuration and stop marker files, and when Agent reads session configuration.
    inline std::wstring queryTempDirectory()
    {
        wchar_t tempBuffer[4096] = {};
        const DWORD kCharCount = ::GetTempPathW(
            static_cast<DWORD>(std::size(tempBuffer)),
            tempBuffer);
        if (kCharCount == 0 || kCharCount >= std::size(tempBuffer))
        {
            return std::wstring(L".");
        }
        return trimTrailingSlash(std::wstring(tempBuffer, kCharCount));
    }

    // buildSessionDirectory：
    // - Purpose: Returns the WinAPI monitoring session directory.
    // - Called: All session files related to pid are placed in this directory to avoid scattering them in the Temp root directory.
    inline std::wstring buildSessionDirectory()
    {
        return joinPath(queryTempDirectory(), L"KswordApiMon");
    }

    // buildPipeNameForPid：
    // - Purpose: Generate a fixed-named pipe based on PID.
    // - Call: UI acts as client to connect; Agent acts as server to create.
    inline std::wstring buildPipeNameForPid(const std::uint32_t pidValue)
    {
        return std::wstring(L"\\\\.\\pipe\\KswordApiMon_") + std::to_wstring(pidValue);
    }

    // buildConfigPathForPid：
    // - Purpose: Generate the session INI configuration file path by PID.
    // - Call: Written by the UI before starting monitoring; read by the Agent after injection.
    inline std::wstring buildConfigPathForPid(const std::uint32_t pidValue)
    {
        return joinPath(
            buildSessionDirectory(),
            std::wstring(L"config_") + std::to_wstring(pidValue) + L".ini");
    }

    // buildStopFlagPathForPid：
    // - Purpose: Generate the 'stop flag' file path based on PID.
    // - Call: UI creates this file when stopping monitoring; the Agent polls in the background to detect it and unload the Hook.
    inline std::wstring buildStopFlagPathForPid(const std::uint32_t pidValue)
    {
        return joinPath(
            buildSessionDirectory(),
            std::wstring(L"stop_") + std::to_wstring(pidValue) + L".flag");
    }

    // eventCategoryToText：
    // - Purpose: Converts the event category enum to a readable wide string.
    // - Invocation: Reused by UI for table rendering and by Agent for generating internal diagnostic text.
    inline std::wstring eventCategoryToText(const EventCategory categoryValue)
    {
        switch (categoryValue)
        {
        case EventCategory::kFile:
            return L"文件";
        case EventCategory::kRegistry:
            return L"注册表";
        case EventCategory::kNetwork:
            return L"网络";
        case EventCategory::kProcess:
            return L"进程";
        case EventCategory::kLoader:
            return L"加载器";
        case EventCategory::kInternal:
            return L"内部";
        default:
            break;
        }
        return L"未知";
    }
}

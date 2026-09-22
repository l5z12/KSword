#include "ProcessDetailCollector.h"

#include "../../core/Common.h"
#include "../../../../shared/ark_client/ArkDriverClient.h"

#include <algorithm>
#include <cstddef>
#include <cwchar>
#include <limits>
#include <psapi.h>
#include <sstream>
#include <tlhelp32.h>
#include <utility>
#include <winternl.h>

namespace ksword::features::process_detail {
namespace {

constexpr DWORD kProcessBasicAccess = PROCESS_QUERY_LIMITED_INFORMATION;
constexpr DWORD kProcessReadAccess = PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ;
constexpr DWORD kThreadQueryAccess = THREAD_QUERY_LIMITED_INFORMATION;
constexpr DWORD kMaxPathBufferChars = 32768;
constexpr ULONG kProcessBasicInformationClass = 0;
constexpr LONG kThreadQuerySetWin32StartAddressClass = 9;

using IsWow64Process2Fn = BOOL(WINAPI*)(HANDLE, USHORT*, USHORT*);
using NtQueryInformationProcessFn = LONG(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
using NtQueryInformationThreadFn = LONG(NTAPI*)(HANDLE, LONG, PVOID, ULONG, PULONG);
using EnumProcessModulesExFn = BOOL(WINAPI*)(HANDLE, HMODULE*, DWORD, LPDWORD, DWORD);
using GetModuleInformationFn = BOOL(WINAPI*)(HANDLE, HMODULE, LPMODULEINFO, DWORD);
using GetModuleFileNameExWFn = DWORD(WINAPI*)(HANDLE, HMODULE, LPWSTR, DWORD);

// NativeProcessBasicInformation is the stable native layout for class 0.
// Inputs come from NtQueryInformationProcess; processing reads only the PEB
// address and inherited PID; output avoids SDK field-name differences.
struct NativeProcessBasicInformation {
    LONG exitStatus = 0;
    PVOID pebBaseAddress = nullptr;
    ULONG_PTR affinityMask = 0;
    LONG basePriority = 0;
    ULONG_PTR uniqueProcessId = 0;
    ULONG_PTR inheritedFromUniqueProcessId = 0;
};

// RemotePeb mirrors only the early PEB fields needed to reach ProcessParameters.
// Input is target memory copied by ReadProcessMemory; processing uses the
// processParameters pointer only; output is not written back to the target.
struct RemotePeb {
    BYTE reserved1[2];
    BYTE beingDebugged = 0;
    BYTE reserved2[1];
    PVOID reserved3[2];
    PVOID ldr = nullptr;
    PVOID processParameters = nullptr;
};

// ModuleApi stores dynamically resolved PSAPI/K32 module enumeration exports.
// Inputs are loader module handles from loadModuleApi; processing never requires
// adding a PSAPI import library to the project; callers check available() first.
struct ModuleApi {
    HMODULE library = nullptr;
    EnumProcessModulesExFn enumProcessModulesEx = nullptr;
    GetModuleInformationFn getModuleInformation = nullptr;
    GetModuleFileNameExWFn getModuleFileNameExW = nullptr;

    // available reports whether every module enumeration export was resolved.
    // There is no input; processing checks stored function pointers; output is
    // true only when collectModules can call the API set safely.
    bool available() const {
        return enumProcessModulesEx && getModuleInformation && getModuleFileNameExW;
    }
};

// NtThreadApi stores optional ntdll thread metadata exports. Inputs are dynamic
// loader results; processing is read-only and optional; callers may continue
// with Toolhelp-only rows when the export is unavailable.
struct NtThreadApi {
    NtQueryInformationThreadFn queryInformationThread = nullptr;

    // available reports whether NtQueryInformationThread was resolved. There is
    // no input; processing checks the stored pointer; output is false when the
    // Threads page must fall back to Toolhelp-only metadata.
    bool available() const {
        return queryInformationThread != nullptr;
    }
};

// RemoteProcessParameters mirrors only the offsets needed for same-bitness
// command-line reading. The structure is deliberately partial because the page
// does not mutate remote memory and only reads ImagePathName/CommandLine.
struct RemoteProcessParameters {
    BYTE reserved1[16];
    PVOID reserved2[10];
    UNICODE_STRING imagePathName;
    UNICODE_STRING commandLine;
};

// formatHexPointer formats an address for list-view display. Input is an
// integer pointer value; processing emits fixed-width hexadecimal text; output
// is a string such as 0x00007FF612340000.
std::wstring formatHexPointer(std::uintptr_t value) {
    std::wostringstream stream;
    stream << L"0x" << std::hex << std::uppercase;
    if (sizeof(void*) == 8) {
        stream.width(16);
    } else {
        stream.width(8);
    }
    stream.fill(L'0');
    stream << value;
    return stream.str();
}

// narrowToWide converts ArkDriverClient diagnostics and row details to UI text.
// Input is UTF-8/ASCII from the shared client; output is best-effort UTF-16.
std::wstring narrowToWide(const std::string& text) {
    if (text.empty()) {
        return {};
    }

    int chars = ::MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0);
    UINT codePage = CP_UTF8;
    if (chars <= 0) {
        codePage = CP_ACP;
        chars = ::MultiByteToWideChar(codePage, 0, text.data(), static_cast<int>(text.size()), nullptr, 0);
    }
    if (chars <= 0) {
        return L"<decode failed>";
    }

    std::wstring wide(static_cast<std::size_t>(chars), L'\0');
    ::MultiByteToWideChar(codePage, 0, text.data(), static_cast<int>(text.size()), wide.data(), chars);
    return wide;
}

// hexMaskText formats raw source/anomaly masks for diagnostics. Input is a
// protocol mask; output remains stable when future bits are added.
std::wstring hexMaskText(ULONG value) {
    std::wostringstream stream;
    stream << L"0x" << std::hex << std::uppercase << value;
    return stream.str();
}

// crossViewSourceText renders shared process/thread source bits. Input is the
// R0 sourceMask; output uses protocol source names shown by the GUI pages.
std::wstring crossViewSourceText(ULONG sourceMask) {
    std::vector<std::wstring> parts;
    if ((sourceMask & KSWORD_ARK_CROSSVIEW_SOURCE_PUBLIC_WALK) != 0) {
        parts.push_back(L"Public");
    }
    if ((sourceMask & KSWORD_ARK_CROSSVIEW_SOURCE_ACTIVE_LIST) != 0) {
        parts.push_back(L"ActiveProcessLinks");
    }
    if ((sourceMask & KSWORD_ARK_CROSSVIEW_SOURCE_CID_TABLE) != 0) {
        parts.push_back(L"CID");
    }
    if ((sourceMask & KSWORD_ARK_CROSSVIEW_SOURCE_THREAD_LIST) != 0) {
        parts.push_back(L"ThreadListHead");
    }
    if (parts.empty()) {
        return L"无来源";
    }

    std::wstring text;
    for (const std::wstring& part : parts) {
        if (!text.empty()) {
            text += L"+";
        }
        text += part;
    }
    return text;
}

// crossViewAnomalyText maps known anomaly flags to readable labels. Input is
// the raw protocol mask; output keeps unknown bits visible for audit export.
std::wstring crossViewAnomalyText(ULONG anomalyFlags) {
    if (anomalyFlags == 0) {
        return L"未见异常";
    }

    std::vector<std::wstring> parts;
    if ((anomalyFlags & KSWORD_ARK_CROSSVIEW_ANOMALY_CID_ONLY) != 0) {
        parts.push_back(L"CID-only");
    }
    if ((anomalyFlags & KSWORD_ARK_CROSSVIEW_ANOMALY_ACTIVE_ONLY) != 0) {
        parts.push_back(L"Active-only");
    }
    if ((anomalyFlags & KSWORD_ARK_CROSSVIEW_ANOMALY_MISSING_FROM_ACTIVE_LIST) != 0) {
        parts.push_back(L"缺ActiveProcessLinks");
    }
    if ((anomalyFlags & KSWORD_ARK_CROSSVIEW_ANOMALY_MISSING_FROM_CID_TABLE) != 0) {
        parts.push_back(L"缺CID");
    }
    if ((anomalyFlags & KSWORD_ARK_CROSSVIEW_ANOMALY_THREAD_ORPHAN) != 0) {
        parts.push_back(L"孤儿线程");
    }
    if ((anomalyFlags & KSWORD_ARK_CROSSVIEW_ANOMALY_THREAD_NOT_IN_PROCESS_LIST) != 0) {
        parts.push_back(L"缺ThreadListHead");
    }
    if ((anomalyFlags & KSWORD_ARK_CROSSVIEW_ANOMALY_START_ADDRESS_OUTSIDE_MODULE) != 0) {
        parts.push_back(L"入口不在模块");
    }
    if ((anomalyFlags & KSWORD_ARK_CROSSVIEW_ANOMALY_PID_FIELD_MISMATCH) != 0) {
        parts.push_back(L"PID不一致");
    }

    std::wstring text;
    for (const std::wstring& part : parts) {
        if (!text.empty()) {
            text += L"; ";
        }
        text += part;
    }
    if (text.empty()) {
        text = L"未知异常位 " + hexMaskText(anomalyFlags);
    }
    return text;
}

// win32ErrorText returns a compact Win32 failure string. Input is an operation
// label and error code; processing appends the formatted system message; output
// is suitable for per-row or per-section status text.
std::wstring win32ErrorText(const wchar_t* operation, DWORD errorCode) {
    return std::wstring(operation) + L" failed: " + ksword::core::lastErrorMessage(errorCode);
}

// resolveProc resolves one function by exact export name. Inputs are a module
// handle and ASCII export name; processing calls GetProcAddress; output is a
// typed function pointer or nullptr.
template <typename Fn>
Fn resolveProc(HMODULE module, const char* name) {
    return module ? reinterpret_cast<Fn>(::GetProcAddress(module, name)) : nullptr;
}

// loadModuleApi resolves module enumeration APIs from kernel32 K32* exports or
// psapi.dll fallback exports. There is no input; processing may load psapi.dll;
// output reports function pointers and keeps the library loaded for process
// lifetime so pointers remain valid.
ModuleApi loadModuleApi() {
    ModuleApi api{};

    HMODULE kernel32 = ::GetModuleHandleW(L"kernel32.dll");
    api.library = kernel32;
    api.enumProcessModulesEx = resolveProc<EnumProcessModulesExFn>(kernel32, "K32EnumProcessModulesEx");
    api.getModuleInformation = resolveProc<GetModuleInformationFn>(kernel32, "K32GetModuleInformation");
    api.getModuleFileNameExW = resolveProc<GetModuleFileNameExWFn>(kernel32, "K32GetModuleFileNameExW");
    if (api.available()) {
        return api;
    }

    HMODULE psapi = ::GetModuleHandleW(L"psapi.dll");
    if (!psapi) {
        psapi = ::LoadLibraryW(L"psapi.dll");
    }
    api.library = psapi;
    api.enumProcessModulesEx = resolveProc<EnumProcessModulesExFn>(psapi, "EnumProcessModulesEx");
    api.getModuleInformation = resolveProc<GetModuleInformationFn>(psapi, "GetModuleInformation");
    api.getModuleFileNameExW = resolveProc<GetModuleFileNameExWFn>(psapi, "GetModuleFileNameExW");
    return api;
}

// loadNtThreadApi resolves NtQueryInformationThread. There is no input;
// processing reads ntdll from the current process; output may be unavailable on
// unusual systems but does not fail the thread snapshot.
NtThreadApi loadNtThreadApi() {
    NtThreadApi api{};
    HMODULE ntdll = ::GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) {
        ntdll = ::LoadLibraryW(L"ntdll.dll");
    }
    api.queryInformationThread = resolveProc<NtQueryInformationThreadFn>(ntdll, "NtQueryInformationThread");
    return api;
}

// queryProcessImagePath reads the target image path through QueryFullProcess-
// ImageNameW. Input is an opened process handle; processing grows a local fixed
// buffer; output is the path or a diagnostic string.
std::wstring queryProcessImagePath(HANDLE process) {
    std::wstring path(kMaxPathBufferChars, L'\0');
    DWORD length = static_cast<DWORD>(path.size());
    if (::QueryFullProcessImageNameW(process, 0, path.data(), &length)) {
        path.resize(length);
        return path;
    }
    return L"<image path unavailable: " + ksword::core::lastErrorMessage() + L">";
}

// leafNameFromPath returns the final path component. Input may be a full DOS
// path or a bare image name; output is empty only when the input is empty.
std::wstring leafNameFromPath(const std::wstring& path) {
    const std::size_t kSeparator = path.find_last_of(L"\\/");
    if (kSeparator == std::wstring::npos) {
        return path;
    }
    return kSeparator + 1U < path.size() ? path.substr(kSeparator + 1U) : std::wstring{};
}

// querySnapshotIdentity uses the public Toolhelp process snapshot to fill the
// target/parent names and the target's snapshot thread count. Inputs are the
// target and parent PIDs; output fields remain unchanged when rows disappeared.
void querySnapshotIdentity(
    DWORD processId,
    DWORD& parentProcessIdInOut,
    std::wstring& processNameOut,
    std::wstring& parentProcessNameOut,
    DWORD& threadCountOut) {
    ksword::core::UniqueHandle snapshot(::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if (!snapshot.valid()) {
        return;
    }

    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (!::Process32FirstW(snapshot.get(), &entry)) {
        return;
    }
    do {
        if (entry.th32ProcessID == processId) {
            processNameOut = entry.szExeFile;
            threadCountOut = entry.cntThreads;
            if (parentProcessIdInOut == 0) {
                parentProcessIdInOut = entry.th32ParentProcessID;
            }
        }
        if (parentProcessIdInOut != 0 && entry.th32ProcessID == parentProcessIdInOut) {
            parentProcessNameOut = entry.szExeFile;
        }
    } while (::Process32NextW(snapshot.get(), &entry));

    // The parent row can sort before the target row, so restart once when the
    // target supplied its PPID after that row had already passed.
    if (parentProcessIdInOut != 0 && parentProcessNameOut.empty()) {
        entry = {};
        entry.dwSize = sizeof(entry);
        if (::Process32FirstW(snapshot.get(), &entry)) {
            do {
                if (entry.th32ProcessID == parentProcessIdInOut) {
                    parentProcessNameOut = entry.szExeFile;
                    break;
                }
            } while (::Process32NextW(snapshot.get(), &entry));
        }
    }
}

// formatProcessStartTime converts a creation FILETIME into local wall-clock
// text. Input is UTC FILETIME; output is YYYY-MM-DD HH:MM:SS or unavailable.
std::wstring formatProcessStartTime(const FILETIME& creationTime) {
    FILETIME localTime{};
    SYSTEMTIME systemTime{};
    if (!::FileTimeToLocalFileTime(&creationTime, &localTime) ||
        !::FileTimeToSystemTime(&localTime, &systemTime)) {
        return L"<start time unavailable>";
    }

    wchar_t text[32]{};
    _snwprintf_s(
        text,
        _countof(text),
        _TRUNCATE,
        L"%04u-%02u-%02u %02u:%02u:%02u",
        systemTime.wYear,
        systemTime.wMonth,
        systemTime.wDay,
        systemTime.wHour,
        systemTime.wMinute,
        systemTime.wSecond);
    return text;
}

// priorityClassText maps GetPriorityClass values to stable user-facing text.
// Input is zero on query failure; output preserves failure as unavailable.
std::wstring priorityClassText(DWORD priorityClass) {
    switch (priorityClass) {
    case IDLE_PRIORITY_CLASS: return L"Idle";
    case BELOW_NORMAL_PRIORITY_CLASS: return L"Below Normal";
    case NORMAL_PRIORITY_CLASS: return L"Normal";
    case ABOVE_NORMAL_PRIORITY_CLASS: return L"Above Normal";
    case HIGH_PRIORITY_CLASS: return L"High";
    case REALTIME_PRIORITY_CLASS: return L"Realtime";
    default: return L"<priority unavailable>";
    }
}

// saturatingAdd64 aggregates monotonically increasing I/O counters without
// wrapping when a long-lived process approaches the unsigned 64-bit limit.
ULONGLONG saturatingAdd64(ULONGLONG left, ULONGLONG right) {
    const ULONGLONG kMaximum = (std::numeric_limits<ULONGLONG>::max)();
    return right > kMaximum - left ? kMaximum : left + right;
}

// queryProcessSession reads the Terminal Services session for one PID. Input is
// processId; processing calls ProcessIdToSessionId; output is zero on failure
// and the caller records a status message separately.
DWORD queryProcessSession(DWORD processId, bool& okOut) {
    DWORD sessionId = 0;
    okOut = ::ProcessIdToSessionId(processId, &sessionId) != FALSE;
    return sessionId;
}

// queryTokenText opens the process token for user and integrity strings. Inputs
// are a process handle and output references; processing uses read-only token
// queries; output strings are diagnostic-safe even when access is denied.
void queryTokenText(
    HANDLE process,
    std::wstring& userOut,
    std::wstring& integrityOut,
    bool& isAdminOut,
    bool& adminKnownOut) {
    isAdminOut = false;
    adminKnownOut = false;
    ksword::core::UniqueHandle token;
    HANDLE rawToken = nullptr;
    if (!::OpenProcessToken(process, TOKEN_QUERY, &rawToken)) {
        const std::wstring kError = ksword::core::lastErrorMessage();
        userOut = L"<token unavailable: " + kError + L">";
        integrityOut = L"<token unavailable: " + kError + L">";
        return;
    }
    token.reset(rawToken);

    TOKEN_ELEVATION elevation{};
    DWORD elevationBytes = 0;
    if (::GetTokenInformation(
            token.get(),
            TokenElevation,
            &elevation,
            sizeof(elevation),
            &elevationBytes)) {
        isAdminOut = elevation.TokenIsElevated != 0;
        adminKnownOut = true;
    }

    DWORD userBytes = 0;
    ::GetTokenInformation(token.get(), TokenUser, nullptr, 0, &userBytes);
    if (userBytes > 0) {
        std::vector<BYTE> userBuffer(userBytes);
        if (::GetTokenInformation(token.get(), TokenUser, userBuffer.data(), userBytes, &userBytes)) {
            const TOKEN_USER* tokenUser = reinterpret_cast<const TOKEN_USER*>(userBuffer.data());
            wchar_t name[256]{};
            wchar_t domain[256]{};
            DWORD nameChars = static_cast<DWORD>(_countof(name));
            DWORD domainChars = static_cast<DWORD>(_countof(domain));
            SID_NAME_USE use{};
            if (::LookupAccountSidW(nullptr, tokenUser->User.Sid, name, &nameChars, domain, &domainChars, &use)) {
                userOut = std::wstring(domain) + L"\\" + name;
            } else {
                userOut = L"<sid lookup failed: " + ksword::core::lastErrorMessage() + L">";
            }
        }
    }
    if (userOut.empty()) {
        userOut = L"<user unavailable>";
    }

    DWORD integrityBytes = 0;
    ::GetTokenInformation(token.get(), TokenIntegrityLevel, nullptr, 0, &integrityBytes);
    if (integrityBytes > 0) {
        std::vector<BYTE> integrityBuffer(integrityBytes);
        if (::GetTokenInformation(token.get(), TokenIntegrityLevel, integrityBuffer.data(), integrityBytes, &integrityBytes)) {
            const TOKEN_MANDATORY_LABEL* label = reinterpret_cast<const TOKEN_MANDATORY_LABEL*>(integrityBuffer.data());
            const DWORD kRid = *::GetSidSubAuthority(label->Label.Sid, static_cast<DWORD>(*::GetSidSubAuthorityCount(label->Label.Sid) - 1));
            if (kRid >= SECURITY_MANDATORY_SYSTEM_RID) {
                integrityOut = L"System";
            } else if (kRid >= SECURITY_MANDATORY_HIGH_RID) {
                integrityOut = L"High";
            } else if (kRid >= SECURITY_MANDATORY_MEDIUM_RID) {
                integrityOut = L"Medium";
            } else if (kRid >= SECURITY_MANDATORY_LOW_RID) {
                integrityOut = L"Low";
            } else {
                integrityOut = L"Untrusted";
            }
        }
    }
    if (integrityOut.empty()) {
        integrityOut = L"<integrity unavailable>";
    }
}

// queryBitnessText determines process architecture without injecting or
// executing target code. Input is process handle; processing prefers
// IsWow64Process2 then falls back to IsWow64Process; output is UI text.
std::wstring queryBitnessText(HANDLE process) {
    HMODULE kernel32 = ::GetModuleHandleW(L"kernel32.dll");
    const auto kIsWow64Process2 = kernel32
        ? reinterpret_cast<IsWow64Process2Fn>(::GetProcAddress(kernel32, "IsWow64Process2"))
        : nullptr;
    if (kIsWow64Process2) {
        USHORT processMachine = 0;
        USHORT nativeMachine = 0;
        if (kIsWow64Process2(process, &processMachine, &nativeMachine)) {
            if (processMachine == IMAGE_FILE_MACHINE_UNKNOWN) {
                return sizeof(void*) == 8 ? L"64-bit native" : L"32-bit native";
            }
            return L"32-bit WOW64";
        }
    }

    BOOL wow64 = FALSE;
    if (::IsWow64Process(process, &wow64)) {
        if (wow64) {
            return L"32-bit WOW64";
        }
        return sizeof(void*) == 8 ? L"64-bit native" : L"32-bit native";
    }
    return L"<bitness unavailable: " + ksword::core::lastErrorMessage() + L">";
}

// queryNativeProcessBasicInformation reads stable class-zero process metadata.
// Input is an opened process handle; output carries PPID, PEB and affinity.
bool queryNativeProcessBasicInformation(HANDLE process, NativeProcessBasicInformation& basicOut) {
    HMODULE ntdll = ::GetModuleHandleW(L"ntdll.dll");
    const auto kQueryProcess = ntdll
        ? reinterpret_cast<NtQueryInformationProcessFn>(::GetProcAddress(ntdll, "NtQueryInformationProcess"))
        : nullptr;
    if (!kQueryProcess) {
        return false;
    }

    basicOut = {};
    ULONG returned = 0;
    return kQueryProcess(
        process,
        kProcessBasicInformationClass,
        &basicOut,
        sizeof(basicOut),
        &returned) >= 0;
}

// queryParentProcessId uses ProcessBasicInformation when available. Input is an
// opened process handle; output is zero when unavailable.
DWORD queryParentProcessId(HANDLE process) {
    NativeProcessBasicInformation basic{};
    return queryNativeProcessBasicInformation(process, basic)
        ? static_cast<DWORD>(basic.inheritedFromUniqueProcessId)
        : 0;
}

// readRemoteUnicodeString copies a UNICODE_STRING value from the target process.
// Inputs are a process handle and a remote string descriptor; processing caps
// the read size and calls ReadProcessMemory once; output is text or a diagnostic.
std::wstring readRemoteUnicodeString(HANDLE process, const UNICODE_STRING& remoteText) {
    if (!remoteText.Buffer || remoteText.Length == 0) {
        return L"";
    }
    if (remoteText.Length > kMaxPathBufferChars * sizeof(wchar_t)) {
        return L"<remote string too large>";
    }

    std::wstring text(remoteText.Length / sizeof(wchar_t), L'\0');
    SIZE_T bytesRead = 0;
    if (!::ReadProcessMemory(process, remoteText.Buffer, text.data(), remoteText.Length, &bytesRead)) {
        return L"<ReadProcessMemory failed: " + ksword::core::lastErrorMessage() + L">";
    }
    text.resize(bytesRead / sizeof(wchar_t));
    return text;
}

// queryCommandLineText reads the target process command line from the PEB when
// readable. Input is a process handle; processing uses NtQueryInformationProcess
// for the PEB address and ReadProcessMemory for ProcessParameters; output is the
// command line or a failure reason without blocking the rest of the page.
std::wstring queryCommandLineText(HANDLE process) {
    NativeProcessBasicInformation basic{};
    if (!queryNativeProcessBasicInformation(process, basic) || !basic.pebBaseAddress) {
        return L"<ProcessBasicInformation unavailable>";
    }

    RemotePeb peb{};
    SIZE_T bytesRead = 0;
    if (!::ReadProcessMemory(process, basic.pebBaseAddress, &peb, sizeof(peb), &bytesRead)) {
        return L"<PEB read failed: " + ksword::core::lastErrorMessage() + L">";
    }

    RemoteProcessParameters parameters{};
    if (!::ReadProcessMemory(process, peb.processParameters, &parameters, sizeof(parameters), &bytesRead)) {
        return L"<ProcessParameters read failed: " + ksword::core::lastErrorMessage() + L">";
    }

    std::wstring commandLine = readRemoteUnicodeString(process, parameters.commandLine);
    if (commandLine.empty()) {
        commandLine = L"<empty command line>";
    }
    return commandLine;
}

// collectBasicInfo reads the basic tab fields. Input is a PID; processing opens
// the process with limited read access and tolerates partial failure; output is
// a filled ProcessBasicInfo plus a success bit.
ProcessBasicInfo collectBasicInfo(DWORD processId, bool& succeededOut) {
    ProcessBasicInfo info{};
    info.processId = processId;
    succeededOut = false;

    querySnapshotIdentity(
        processId,
        info.parentProcessId,
        info.processName,
        info.parentProcessName,
        info.threadCount);

    HANDLE rawProcess = ::OpenProcess(kProcessBasicAccess, FALSE, processId);
    ksword::core::UniqueHandle process(rawProcess);
    if (!process.valid()) {
        info.statusText = win32ErrorText(L"OpenProcess", ::GetLastError());
        return info;
    }

    succeededOut = true;
    const DWORD kNativeParentProcessId = queryParentProcessId(process.get());
    if (kNativeParentProcessId != 0) {
        info.parentProcessId = kNativeParentProcessId;
    }
    info.imagePath = queryProcessImagePath(process.get());
    if (!info.imagePath.empty() && info.imagePath.front() != L'<') {
        info.processName = leafNameFromPath(info.imagePath);
    }
    querySnapshotIdentity(
        processId,
        info.parentProcessId,
        info.processName,
        info.parentProcessName,
        info.threadCount);

    NativeProcessBasicInformation nativeBasic{};
    if (queryNativeProcessBasicInformation(process.get(), nativeBasic)) {
        if (nativeBasic.pebBaseAddress) {
            info.pebAddress = reinterpret_cast<std::uintptr_t>(nativeBasic.pebBaseAddress);
            info.pebAddressKnown = true;
        }
        if (nativeBasic.affinityMask != 0) {
            info.affinityMask = static_cast<std::uint64_t>(nativeBasic.affinityMask);
            info.affinityKnown = true;
        }
    }

    ksword::core::UniqueHandle readableProcess(::OpenProcess(kProcessReadAccess, FALSE, processId));
    info.commandLine = readableProcess.valid()
        ? queryCommandLineText(readableProcess.get())
        : L"<command line unavailable: " + ksword::core::lastErrorMessage() + L">";
    info.bitness = queryBitnessText(process.get());
    bool sessionOk = false;
    info.sessionId = queryProcessSession(processId, sessionOk);
    const DWORD kSessionError = sessionOk ? ERROR_SUCCESS : ::GetLastError();
    queryTokenText(
        process.get(),
        info.userName,
        info.integrityLevel,
        info.isAdmin,
        info.adminKnown);

    FILETIME creationTime{};
    FILETIME exitTime{};
    FILETIME kernelTime{};
    FILETIME userTime{};
    info.startTimeText = ::GetProcessTimes(
        process.get(),
        &creationTime,
        &exitTime,
        &kernelTime,
        &userTime)
        ? formatProcessStartTime(creationTime)
        : L"<start time unavailable>";

    info.priorityText = priorityClassText(::GetPriorityClass(process.get()));
    DWORD handleCount = 0;
    if (::GetProcessHandleCount(process.get(), &handleCount)) {
        info.handleCount = handleCount;
    }

    DWORD_PTR processAffinity = 0;
    DWORD_PTR systemAffinity = 0;
    if (::GetProcessAffinityMask(process.get(), &processAffinity, &systemAffinity)) {
        info.affinityMask = static_cast<std::uint64_t>(processAffinity);
        info.affinityKnown = true;
    }

    PROCESS_MEMORY_COUNTERS_EX memoryCounters{};
    memoryCounters.cb = sizeof(memoryCounters);
    HANDLE memoryProcess = readableProcess.valid() ? readableProcess.get() : process.get();
    if (::GetProcessMemoryInfo(
            memoryProcess,
            reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&memoryCounters),
            sizeof(memoryCounters))) {
        info.workingSetBytes = static_cast<ULONGLONG>(memoryCounters.WorkingSetSize);
        info.privateBytes = static_cast<ULONGLONG>(memoryCounters.PrivateUsage);
    }

    IO_COUNTERS ioCounters{};
    if (::GetProcessIoCounters(process.get(), &ioCounters)) {
        info.ioBytes = saturatingAdd64(
            saturatingAdd64(ioCounters.ReadTransferCount, ioCounters.WriteTransferCount),
            ioCounters.OtherTransferCount);
    }
    info.statusText = sessionOk
        ? L"OK"
        : L"OK; session unavailable: " + ksword::core::lastErrorMessage(kSessionError);
    return info;
}

// collectThreads enumerates threads owned by the target PID. Input is processId;
// processing uses CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD), then revalidates
// each opened thread's owner and creation time before retaining it in the snapshot.
std::vector<ProcessThreadInfo> collectThreads(DWORD processId, bool& succeededOut, std::wstring& statusOut) {
    succeededOut = false;
    statusOut.clear();
    std::vector<ProcessThreadInfo> rows;
    const NtThreadApi kThreadApi = loadNtThreadApi();

    ksword::core::UniqueHandle snapshot(::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0));
    if (!snapshot.valid()) {
        statusOut = win32ErrorText(L"CreateToolhelp32Snapshot(THREAD)", ::GetLastError());
        return rows;
    }

    THREADENTRY32 entry{};
    entry.dwSize = sizeof(entry);
    if (!::Thread32First(snapshot.get(), &entry)) {
        statusOut = win32ErrorText(L"Thread32First", ::GetLastError());
        return rows;
    }

    do {
        if (entry.th32OwnerProcessID != processId) {
            continue;
        }

        ProcessThreadInfo row{};
        row.threadId = entry.th32ThreadID;
        row.ownerProcessId = entry.th32OwnerProcessID;
        row.basePriority = entry.tpBasePri;
        row.deltaPriority = entry.tpDeltaPri;
        row.suspendCount = 0;

        ksword::core::UniqueHandle thread(::OpenThread(kThreadQueryAccess, FALSE, row.threadId));
        if (!thread.valid()) {
            row.statusText = L"OpenThread limited info failed: " + ksword::core::lastErrorMessage();
            rows.push_back(std::move(row));
            continue;
        }

        const DWORD kActualOwnerProcessId = ::GetProcessIdOfThread(thread.get());
        if (kActualOwnerProcessId == 0U || kActualOwnerProcessId != processId) {
            // The Toolhelp entry became stale before OpenThread completed. Do not
            // retain a row that could later represent another process's thread.
            continue;
        }
        row.ownerProcessId = kActualOwnerProcessId;

        FILETIME creationTime{};
        FILETIME exitTime{};
        FILETIME kernelTime{};
        FILETIME userTime{};
        const BOOL kCreationTimeOk = ::GetThreadTimes(
            thread.get(),
            &creationTime,
            &exitTime,
            &kernelTime,
            &userTime);
        if (kCreationTimeOk) {
            row.creationTime100ns =
                (static_cast<ULONGLONG>(creationTime.dwHighDateTime) << 32U) |
                static_cast<ULONGLONG>(creationTime.dwLowDateTime);
        } else {
            row.statusText = L"GetThreadTimes failed: " + ksword::core::lastErrorMessage();
        }

        if (kThreadApi.available()) {
            PVOID startAddress = nullptr;
            const LONG kStatus = kThreadApi.queryInformationThread(
                thread.get(),
                kThreadQuerySetWin32StartAddressClass,
                &startAddress,
                sizeof(startAddress),
                nullptr);
            if (kStatus >= 0) {
                row.startAddress = reinterpret_cast<std::uintptr_t>(startAddress);
                if (kCreationTimeOk) {
                    row.statusText = L"OK";
                }
            } else if (kCreationTimeOk) {
                row.statusText = L"NtQueryInformationThread failed";
            }
        } else if (kCreationTimeOk) {
            row.statusText = L"OK; NtQueryInformationThread unavailable";
        }
        rows.push_back(std::move(row));
    } while (::Thread32Next(snapshot.get(), &entry));

    succeededOut = true;
    statusOut = L"OK";
    std::sort(rows.begin(), rows.end(), [](const ProcessThreadInfo& left, const ProcessThreadInfo& right) {
        return left.threadId < right.threadId;
    });
    return rows;
}

// baseNameFromPath extracts the final path component. Input is a full path;
// processing searches slash and backslash separators; output is never longer
// than the input and may equal the input for bare names.
std::wstring baseNameFromPath(const std::wstring& path) {
    const std::size_t kPos = path.find_last_of(L"\\/");
    if (kPos == std::wstring::npos || kPos + 1 >= path.size()) {
        return path;
    }
    return path.substr(kPos + 1);
}

// collectModules enumerates modules loaded in the process. Input is processId;
// processing uses EnumProcessModulesEx and GetModuleInformation/GetModuleFile-
// NameExW; output is sorted by base address with per-row status.
std::vector<ProcessModuleInfo> collectModules(DWORD processId, bool& succeededOut, std::wstring& statusOut) {
    succeededOut = false;
    statusOut.clear();
    std::vector<ProcessModuleInfo> rows;

    const ModuleApi kModuleApi = loadModuleApi();
    if (!kModuleApi.available()) {
        statusOut = L"Module enumeration API unavailable.";
        return rows;
    }

    ksword::core::UniqueHandle process(::OpenProcess(kProcessReadAccess, FALSE, processId));
    if (!process.valid()) {
        statusOut = win32ErrorText(L"OpenProcess", ::GetLastError());
        return rows;
    }

    DWORD neededBytes = 0;
    std::vector<HMODULE> modules(256);
    if (!kModuleApi.enumProcessModulesEx(process.get(), modules.data(), static_cast<DWORD>(modules.size() * sizeof(HMODULE)), &neededBytes, LIST_MODULES_ALL)) {
        statusOut = win32ErrorText(L"EnumProcessModulesEx", ::GetLastError());
        return rows;
    }
    if (neededBytes > modules.size() * sizeof(HMODULE)) {
        modules.resize(neededBytes / sizeof(HMODULE));
        if (!kModuleApi.enumProcessModulesEx(process.get(), modules.data(), static_cast<DWORD>(modules.size() * sizeof(HMODULE)), &neededBytes, LIST_MODULES_ALL)) {
            statusOut = win32ErrorText(L"EnumProcessModulesEx retry", ::GetLastError());
            return rows;
        }
    }
    modules.resize(neededBytes / sizeof(HMODULE));

    for (HMODULE module : modules) {
        ProcessModuleInfo row{};
        MODULEINFO moduleInfo{};
        if (kModuleApi.getModuleInformation(process.get(), module, &moduleInfo, sizeof(moduleInfo))) {
            row.baseAddress = reinterpret_cast<std::uintptr_t>(moduleInfo.lpBaseOfDll);
            row.imageSize = moduleInfo.SizeOfImage;
        }

        std::wstring path(MAX_PATH, L'\0');
        DWORD copied = kModuleApi.getModuleFileNameExW(process.get(), module, path.data(), static_cast<DWORD>(path.size()));
        if (copied >= path.size() - 1) {
            path.resize(kMaxPathBufferChars, L'\0');
            copied = kModuleApi.getModuleFileNameExW(process.get(), module, path.data(), static_cast<DWORD>(path.size()));
        }
        if (copied > 0) {
            path.resize(copied);
            row.modulePath = path;
            row.moduleName = baseNameFromPath(path);
            row.statusText = L"OK";
        } else {
            row.moduleName = formatHexPointer(reinterpret_cast<std::uintptr_t>(module));
            row.modulePath = L"<module path unavailable>";
            row.statusText = win32ErrorText(L"GetModuleFileNameExW", ::GetLastError());
        }
        rows.push_back(std::move(row));
    }

    succeededOut = true;
    statusOut = L"OK";
    std::sort(rows.begin(), rows.end(), [](const ProcessModuleInfo& left, const ProcessModuleInfo& right) {
        return left.baseAddress < right.baseAddress;
    });
    return rows;
}

// attachRepresentativeThreads maps already-collected thread start addresses to
// loaded module address ranges. Inputs are the module rows and thread rows from
// the same PID snapshot; processing chooses the first thread whose Win32 start
// address lies inside each module; no value is returned because modules are
// updated in place for the Modules tab context menu.
void attachRepresentativeThreads(
    std::vector<ProcessModuleInfo>& modules,
    const std::vector<ProcessThreadInfo>& threads) {
    if (modules.empty() || threads.empty()) {
        return;
    }

    for (ProcessModuleInfo& module : modules) {
        const std::uintptr_t kModuleStart = module.baseAddress;
        const std::uintptr_t kModuleEnd = kModuleStart + static_cast<std::uintptr_t>(module.imageSize);
        if (kModuleStart == 0 || kModuleEnd <= kModuleStart) {
            continue;
        }

        for (const ProcessThreadInfo& thread : threads) {
            if (thread.creationTime100ns != 0U &&
                thread.startAddress >= kModuleStart && thread.startAddress < kModuleEnd) {
                module.representativeThreadId = thread.threadId;
                module.representativeThreadCreationTime100ns = thread.creationTime100ns;
                break;
            }
        }
    }
}

// addR0AuditRow appends one read-only driver evidence row to the process_detail
// R0 tab. Inputs are the target vector and display-ready scalar fields;
// processing preserves object addresses only for display and never feeds them
// into write operations; there is no return value.
void addR0AuditRow(
    std::vector<ProcessR0AuditInfo>& rows,
    const std::wstring& scope,
    DWORD processId,
    DWORD threadId,
    std::uint64_t objectAddress,
    std::uint64_t relatedObjectAddress,
    std::uint64_t startAddress,
    const std::wstring& sourceText,
    const std::wstring& statusText,
    ULONG confidence,
    const std::wstring& detailText) {
    ProcessR0AuditInfo row{};
    row.scope = scope;
    row.processId = processId;
    row.threadId = threadId;
    row.objectAddress = static_cast<std::uintptr_t>(objectAddress);
    row.relatedObjectAddress = static_cast<std::uintptr_t>(relatedObjectAddress);
    row.startAddress = static_cast<std::uintptr_t>(startAddress);
    row.confidence = confidence;
    row.sourceText = sourceText;
    row.anomalyText = statusText;
    row.detailText = detailText;
    rows.push_back(std::move(row));
}

// statusHexText renders an NTSTATUS/LONG as fixed hexadecimal text. Input is a
// signed status value from the driver protocol; output is a UI diagnostic token.
std::wstring statusHexText(long status) {
    std::wostringstream stream;
    stream << L"0x" << std::hex << std::uppercase << static_cast<unsigned long>(status);
    return stream.str();
}

// buildProcessRuntimeSampleItems derives safe field-sample requests from the
// fixed process detail response. Inputs are offsets already returned by R0;
// processing keeps only known, bounded EPROCESS fields; output is suitable for
// ArkDriverClient::queryProcessRuntimeFieldSamples.
std::vector<ksword::ark::RuntimeFieldSampleRequestItem> buildProcessRuntimeSampleItems(
    const KSWORD_ARK_PROCESS_DETAIL_RESPONSE& detail) {
    std::vector<ksword::ark::RuntimeFieldSampleRequestItem> items;
    const auto kAdd = [&](std::uint32_t id, std::uint32_t offset, std::uint32_t size, const char* name, const char* type) {
        if (offset == KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE || size == 0 || size > KSWORD_ARK_RUNTIME_FIELD_SAMPLE_MAX_VALUE_BYTES) {
            return;
        }
        ksword::ark::RuntimeFieldSampleRequestItem item{};
        item.runtimeItemId = id;
        item.offset = offset;
        item.size = size;
        item.name = name;
        item.type = type;
        items.push_back(std::move(item));
    };
    kAdd(KSW_DYN_FIELD_ID_EP_UNIQUE_PROCESS_ID, detail.offsets.epUniqueProcessId, sizeof(std::uint64_t), "EP.UniqueProcessId", "HANDLE");
    kAdd(KSW_DYN_FIELD_ID_EP_ACTIVE_PROCESS_LINKS, detail.offsets.epActiveProcessLinks, sizeof(std::uint64_t), "EP.ActiveProcessLinks", "LIST_ENTRY.Flink");
    kAdd(KSW_DYN_FIELD_ID_EP_THREAD_LIST_HEAD, detail.offsets.epThreadListHead, sizeof(std::uint64_t), "EP.ThreadListHead", "LIST_ENTRY.Flink");
    kAdd(KSW_DYN_FIELD_ID_EP_TOKEN, detail.offsets.epToken, sizeof(std::uint64_t), "EP.Token", "EX_FAST_REF");
    kAdd(KSW_DYN_FIELD_ID_EP_OBJECT_TABLE, detail.offsets.epObjectTable, sizeof(std::uint64_t), "EP.ObjectTable", "EXHANDLE_TABLE*");
    kAdd(KSW_DYN_FIELD_ID_EP_SECTION_OBJECT, detail.offsets.epSectionObject, sizeof(std::uint64_t), "EP.SectionObject", "SECTION_OBJECT*");
    kAdd(KSW_DYN_FIELD_ID_EP_PROTECTION, detail.offsets.epProtection, sizeof(std::uint8_t), "EP.Protection", "PS_PROTECTION");
    kAdd(KSW_DYN_FIELD_ID_EP_SIGNATURE_LEVEL, detail.offsets.epSignatureLevel, sizeof(std::uint8_t), "EP.SignatureLevel", "UCHAR");
    kAdd(KSW_DYN_FIELD_ID_EP_SECTION_SIGNATURE_LEVEL, detail.offsets.epSectionSignatureLevel, sizeof(std::uint8_t), "EP.SectionSignatureLevel", "UCHAR");
    return items;
}

// buildThreadRuntimeSampleItems derives safe field-sample requests from the
// fixed thread detail response. Inputs are R0-provided ETHREAD/KTHREAD offsets;
// processing keeps known field sizes under the protocol cap; output is suitable
// for ArkDriverClient::queryThreadRuntimeFieldSamples.
std::vector<ksword::ark::RuntimeFieldSampleRequestItem> buildThreadRuntimeSampleItems(
    const KSWORD_ARK_THREAD_DETAIL_RESPONSE& detail) {
    std::vector<ksword::ark::RuntimeFieldSampleRequestItem> items;
    const auto kAdd = [&](std::uint32_t id, std::uint32_t offset, std::uint32_t size, const char* name, const char* type) {
        if (offset == KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE || size == 0 || size > KSWORD_ARK_RUNTIME_FIELD_SAMPLE_MAX_VALUE_BYTES) {
            return;
        }
        ksword::ark::RuntimeFieldSampleRequestItem item{};
        item.runtimeItemId = id;
        item.offset = offset;
        item.size = size;
        item.name = name;
        item.type = type;
        items.push_back(std::move(item));
    };
    kAdd(KSW_DYN_FIELD_ID_ET_CID, detail.offsets.etCid, sizeof(std::uint64_t) * 2U, "ET.Cid", "CLIENT_ID");
    kAdd(KSW_DYN_FIELD_ID_ET_THREAD_LIST_ENTRY, detail.offsets.etThreadListEntry, sizeof(std::uint64_t), "ET.ThreadListEntry", "LIST_ENTRY.Flink");
    kAdd(KSW_DYN_FIELD_ID_ET_START_ADDRESS, detail.offsets.etStartAddress, sizeof(std::uint64_t), "ET.StartAddress", "PVOID");
    kAdd(KSW_DYN_FIELD_ID_ET_WIN32_START_ADDRESS, detail.offsets.etWin32StartAddress, sizeof(std::uint64_t), "ET.Win32StartAddress", "PVOID");
    kAdd(KSW_DYN_FIELD_ID_KT_PROCESS, detail.offsets.ktProcess, sizeof(std::uint64_t), "KT.Process", "KPROCESS*");
    kAdd(KSW_DYN_FIELD_ID_KT_INITIAL_STACK, detail.offsets.ktInitialStack, sizeof(std::uint64_t), "KT.InitialStack", "PVOID");
    kAdd(KSW_DYN_FIELD_ID_KT_STACK_LIMIT, detail.offsets.ktStackLimit, sizeof(std::uint64_t), "KT.StackLimit", "PVOID");
    kAdd(KSW_DYN_FIELD_ID_KT_STACK_BASE, detail.offsets.ktStackBase, sizeof(std::uint64_t), "KT.StackBase", "PVOID");
    kAdd(KSW_DYN_FIELD_ID_KT_KERNEL_STACK, detail.offsets.ktKernelStack, sizeof(std::uint64_t), "KT.KernelStack", "PVOID");
    kAdd(KSW_DYN_FIELD_ID_KT_READ_OPERATION_COUNT, detail.offsets.ktReadOperationCount, sizeof(std::uint64_t), "KT.ReadOperationCount", "ULONGLONG");
    kAdd(KSW_DYN_FIELD_ID_KT_WRITE_OPERATION_COUNT, detail.offsets.ktWriteOperationCount, sizeof(std::uint64_t), "KT.WriteOperationCount", "ULONGLONG");
    kAdd(KSW_DYN_FIELD_ID_KT_OTHER_OPERATION_COUNT, detail.offsets.ktOtherOperationCount, sizeof(std::uint64_t), "KT.OtherOperationCount", "ULONGLONG");
    return items;
}

// collectR0AuditRows queries process/thread cross-view through ArkDriverClient.
// Inputs are a PID and status outputs; processing is read-only and bounded by
// the shared cross-view max-node defaults; output rows are UI evidence only.
std::vector<ProcessR0AuditInfo> collectR0AuditRows(DWORD processId, bool& succeededOut, std::wstring& statusOut) {
    succeededOut = false;
    statusOut.clear();
    std::vector<ProcessR0AuditInfo> rows;

    const ksword::ark::DriverClient kDriverClient;
    const ksword::ark::ThreadEnumResult kThreadEnumeration = kDriverClient.enumerateThreads(
        KSWORD_ARK_ENUM_THREAD_FLAG_INCLUDE_ALL | KSWORD_ARK_ENUM_THREAD_FLAG_SCAN_CID_TABLE,
        processId);
    if (!kThreadEnumeration.io.ok) {
        addR0AuditRow(
            rows,
            L"ThreadEnumeration",
            processId,
            0,
            0,
            0,
            0,
            L"ArkDriverClient::enumerateThreads",
            L"Unavailable",
            0,
            narrowToWide(kThreadEnumeration.io.message));
    } else {
        addR0AuditRow(
            rows,
            L"ThreadEnumeration",
            processId,
            0,
            0,
            0,
            0,
            L"ArkDriverClient::enumerateThreads",
            L"OK",
            100,
            L"returned=" + std::to_wstring(kThreadEnumeration.returnedCount) +
                L"/" + std::to_wstring(kThreadEnumeration.totalCount) +
                L"; version=" + std::to_wstring(kThreadEnumeration.version));
        constexpr std::size_t kMaxThreadEnumerationRows = 512U;
        const std::size_t kEntryCount = (std::min)(kThreadEnumeration.entries.size(), kMaxThreadEnumerationRows);
        for (std::size_t index = 0; index < kEntryCount; ++index) {
            const ksword::ark::ThreadEntry& entry = kThreadEnumeration.entries[index];
            std::wostringstream detail;
            detail << L"flags=" << hexMaskText(entry.flags)
                   << L"; fieldFlags=" << hexMaskText(entry.fieldFlags)
                   << L"; r0Status=" << entry.r0Status
                   << L"; initialStack=" << formatHexPointer(static_cast<std::uintptr_t>(entry.initialStack))
                   << L"; stack=" << formatHexPointer(static_cast<std::uintptr_t>(entry.stackLimit))
                   << L"-" << formatHexPointer(static_cast<std::uintptr_t>(entry.stackBase))
                   << L"; kernelStack=" << formatHexPointer(static_cast<std::uintptr_t>(entry.kernelStack))
                   << L"; io=R" << entry.readOperationCount
                   << L"/W" << entry.writeOperationCount
                   << L"/O" << entry.otherOperationCount
                   << L"; transfer=R" << entry.readTransferCount
                   << L"/W" << entry.writeTransferCount
                   << L"/O" << entry.otherTransferCount
                   << L"; capability=" << formatHexPointer(static_cast<std::uintptr_t>(entry.dynDataCapabilityMask));
            addR0AuditRow(
                rows,
                L"ThreadEnumeration",
                static_cast<DWORD>(entry.processId),
                static_cast<DWORD>(entry.threadId),
                entry.kernelStack,
                entry.initialStack,
                entry.stackBase,
                L"R0 KTHREAD",
                entry.r0Status == KSWORD_ARK_THREAD_R0_STATUS_OK ? L"OK" : L"Partial",
                entry.r0Status == KSWORD_ARK_THREAD_R0_STATUS_OK ? 100UL : 50UL,
                detail.str());
        }
        if (kThreadEnumeration.entries.size() > kEntryCount) {
            addR0AuditRow(
                rows,
                L"ThreadEnumeration",
                processId,
                0,
                0,
                0,
                0,
                L"R0 KTHREAD",
                L"Truncated",
                0,
                L"Light limits visible R0 thread enumeration evidence to " + std::to_wstring(kMaxThreadEnumerationRows) + L" rows per refresh.");
        }
    }

    const ksword::ark::ProcessSectionQueryResult kSectionQuery = kDriverClient.queryProcessSection(processId);
    if (!kSectionQuery.io.ok) {
        addR0AuditRow(
            rows,
            L"ProcessSection",
            processId,
            0,
            kSectionQuery.sectionObjectAddress,
            kSectionQuery.controlAreaAddress,
            0,
            L"ArkDriverClient::queryProcessSection",
            L"Unavailable",
            0,
            narrowToWide(kSectionQuery.io.message));
    } else {
        addR0AuditRow(
            rows,
            L"ProcessSection",
            processId,
            0,
            kSectionQuery.sectionObjectAddress,
            kSectionQuery.controlAreaAddress,
            0,
            L"ArkDriverClient::queryProcessSection",
            L"OK",
            100,
            L"returned=" + std::to_wstring(kSectionQuery.returnedCount) +
                L"/" + std::to_wstring(kSectionQuery.totalCount) +
                L"; queryStatus=" + std::to_wstring(kSectionQuery.queryStatus) +
                L"; fieldFlags=" + hexMaskText(kSectionQuery.fieldFlags) +
                L"; lastStatus=" + statusHexText(kSectionQuery.lastStatus));
        for (const ksword::ark::SectionMappingEntry& mapping : kSectionQuery.mappings) {
            addR0AuditRow(
                rows,
                L"ProcessSectionMapping",
                static_cast<DWORD>(mapping.processId),
                0,
                kSectionQuery.sectionObjectAddress,
                kSectionQuery.controlAreaAddress,
                mapping.startVa,
                L"ControlArea mapping",
                L"type=" + std::to_wstring(mapping.viewMapType),
                100,
                L"start=" + formatHexPointer(static_cast<std::uintptr_t>(mapping.startVa)) +
                    L"; end=" + formatHexPointer(static_cast<std::uintptr_t>(mapping.endVa)) +
                    L"; mapType=" + std::to_wstring(mapping.viewMapType));
        }
    }

    const ksword::ark::ProcessCrossViewResult kProcessAudit = kDriverClient.queryProcessCrossView(
        KSWORD_ARK_PROCESS_CROSSVIEW_FLAG_INCLUDE_ALL,
        processId,
        processId,
        KSWORD_ARK_CROSSVIEW_DEFAULT_MAX_NODES);
    if (!kProcessAudit.io.ok) {
        statusOut = L"Process cross-view failed: " + narrowToWide(kProcessAudit.io.message);
    } else {
        for (const ksword::ark::ProcessCrossViewEntry& entry : kProcessAudit.entries) {
            if (entry.processId != processId) {
                continue;
            }
            ProcessR0AuditInfo row{};
            row.scope = L"Process";
            row.processId = static_cast<DWORD>(entry.processId);
            row.objectAddress = static_cast<std::uintptr_t>(entry.objectAddress);
            row.startAddress = static_cast<std::uintptr_t>(entry.startAddress);
            row.sourceMask = entry.sourceMask;
            row.anomalyFlags = entry.anomalyFlags;
            row.confidence = entry.confidence;
            row.sourceText = crossViewSourceText(row.sourceMask);
            row.anomalyText = crossViewAnomalyText(row.anomalyFlags);
            row.detailText = narrowToWide(entry.detail);
            rows.push_back(std::move(row));
        }
    }

    const ksword::ark::ThreadCrossViewResult kThreadAudit = kDriverClient.queryThreadCrossView(
        KSWORD_ARK_THREAD_CROSSVIEW_FLAG_INCLUDE_ALL,
        processId,
        0,
        0,
        KSWORD_ARK_CROSSVIEW_DEFAULT_MAX_NODES);
    if (!kThreadAudit.io.ok) {
        if (!statusOut.empty()) {
            statusOut += L"; ";
        }
        statusOut += L"Thread cross-view failed: " + narrowToWide(kThreadAudit.io.message);
    } else {
        for (const ksword::ark::ThreadCrossViewEntry& entry : kThreadAudit.entries) {
            if (entry.processId != processId) {
                continue;
            }
            ProcessR0AuditInfo row{};
            row.scope = L"Thread";
            row.processId = static_cast<DWORD>(entry.processId);
            row.threadId = static_cast<DWORD>(entry.threadId);
            row.objectAddress = static_cast<std::uintptr_t>(entry.objectAddress);
            row.relatedObjectAddress = static_cast<std::uintptr_t>(entry.processObjectAddress);
            row.startAddress = static_cast<std::uintptr_t>(entry.startAddress);
            row.sourceMask = entry.sourceMask;
            row.anomalyFlags = entry.anomalyFlags;
            row.confidence = entry.confidence;
            row.sourceText = crossViewSourceText(row.sourceMask);
            row.anomalyText = crossViewAnomalyText(row.anomalyFlags);
            row.detailText = narrowToWide(entry.detail);
            rows.push_back(std::move(row));
        }
    }

    const ksword::ark::ProcessRuntimeDetailResult kProcessDetail =
        kDriverClient.queryProcessRuntimeDetail(processId);
    if (!kProcessDetail.io.ok) {
        addR0AuditRow(
            rows,
            L"ProcessDetail",
            processId,
            0,
            0,
            0,
            0,
            L"ArkDriverClient::queryProcessRuntimeDetail",
            kProcessDetail.unsupported ? L"Unsupported" : L"Unavailable",
            0,
            narrowToWide(kProcessDetail.io.message));
    } else {
        const KSWORD_ARK_PROCESS_DETAIL_RESPONSE& detail = kProcessDetail.response;
        std::wostringstream text;
        text << L"fields=" << hexMaskText(detail.fieldFlags)
             << L"; requested=" << hexMaskText(detail.requestedFlags)
             << L"; dyn=" << formatHexPointer(static_cast<std::uintptr_t>(detail.dynDataCapabilityMask))
             << L"; missing=" << formatHexPointer(static_cast<std::uintptr_t>(detail.missingCapabilityMask))
             << L"; token=" << formatHexPointer(static_cast<std::uintptr_t>(detail.tokenObjectAddress))
             << L"; objectTable=" << formatHexPointer(static_cast<std::uintptr_t>(detail.objectTableAddress))
             << L"; section=" << formatHexPointer(static_cast<std::uintptr_t>(detail.sectionObjectAddress))
             << L"; detail=" << std::wstring(detail.detail);
        addR0AuditRow(
            rows,
            L"ProcessDetail",
            processId,
            0,
            detail.processObjectAddress,
            detail.tokenObjectAddress,
            0,
            L"IOCTL_KSWORD_ARK_QUERY_PROCESS_DETAIL",
            L"status=" + std::to_wstring(detail.status) + L", last=" + statusHexText(detail.lastStatus),
            100,
            text.str());

        const std::vector<ksword::ark::RuntimeFieldSampleRequestItem> kSampleItems =
            buildProcessRuntimeSampleItems(detail);
        if (!kSampleItems.empty()) {
            const ksword::ark::RuntimeFieldSampleResult kSamples =
                kDriverClient.queryProcessRuntimeFieldSamples(processId, kSampleItems);
            addR0AuditRow(
                rows,
                L"ProcessRuntimeFields",
                processId,
                0,
                kSamples.objectAddress,
                0,
                0,
                L"IOCTL_KSWORD_ARK_QUERY_PROCESS_RUNTIME_FIELDS",
                kSamples.io.ok ? L"OK" : (kSamples.unsupported ? L"Unsupported" : L"Unavailable"),
                kSamples.io.ok ? 100UL : 0UL,
                L"returned=" + std::to_wstring(kSamples.returnedCount) +
                    L"/" + std::to_wstring(kSamples.totalCount) +
                    L"; status=" + std::to_wstring(kSamples.status) +
                    L"; " + narrowToWide(kSamples.io.message));
            for (const ksword::ark::RuntimeFieldSampleEntry& entry : kSamples.entries) {
                addR0AuditRow(
                    rows,
                    L"ProcessField",
                    processId,
                    0,
                    kSamples.objectAddress,
                    0,
                    0,
                    narrowToWide(entry.name.empty() ? std::string("runtime-field") : entry.name),
                    L"rowStatus=" + std::to_wstring(entry.status),
                    entry.status == KSWORD_ARK_RUNTIME_FIELD_SAMPLE_ROW_STATUS_OK ? 100UL : 50UL,
                    L"id=" + std::to_wstring(entry.runtimeItemId) +
                        L"; offset=" + hexMaskText(entry.offset) +
                        L"; size=" + std::to_wstring(entry.size) +
                        L"; bytesRead=" + std::to_wstring(entry.bytesRead) +
                        L"; value=" + formatHexPointer(static_cast<std::uintptr_t>(entry.valueU64)) +
                        L"; last=" + statusHexText(entry.lastStatus));
            }
        }
    }

    std::size_t threadDetailCount = 0U;
    for (const ksword::ark::ThreadCrossViewEntry& entry : kThreadAudit.entries) {
        if (entry.processId != processId || entry.threadId == 0U) {
            continue;
        }
        if (threadDetailCount >= 128U) {
            addR0AuditRow(
                rows,
                L"ThreadDetail",
                processId,
                0,
                0,
                0,
                0,
                L"ArkDriverClient::queryThreadRuntimeDetail",
                L"Truncated",
                0,
                L"Thread runtime detail rows are capped at 128 per refresh to keep the Light GUI responsive.");
            break;
        }
        ++threadDetailCount;
        const ksword::ark::ThreadRuntimeDetailResult kThreadDetail =
            kDriverClient.queryThreadRuntimeDetail(entry.threadId, processId);
        if (!kThreadDetail.io.ok) {
            addR0AuditRow(
                rows,
                L"ThreadDetail",
                processId,
                entry.threadId,
                entry.objectAddress,
                entry.processObjectAddress,
                entry.startAddress,
                L"ArkDriverClient::queryThreadRuntimeDetail",
                kThreadDetail.unsupported ? L"Unsupported" : L"Unavailable",
                0,
                narrowToWide(kThreadDetail.io.message));
            continue;
        }

        const KSWORD_ARK_THREAD_DETAIL_RESPONSE& detail = kThreadDetail.response;
        std::wostringstream text;
        text << L"fields=" << hexMaskText(detail.fieldFlags)
             << L"; requested=" << hexMaskText(detail.requestedFlags)
             << L"; cidPid=" << formatHexPointer(static_cast<std::uintptr_t>(detail.cidUniqueProcess))
             << L"; cidTid=" << formatHexPointer(static_cast<std::uintptr_t>(detail.cidUniqueThread))
             << L"; start=" << formatHexPointer(static_cast<std::uintptr_t>(detail.startAddress))
             << L"; win32Start=" << formatHexPointer(static_cast<std::uintptr_t>(detail.win32StartAddress))
             << L"; stack=" << formatHexPointer(static_cast<std::uintptr_t>(detail.stackLimit))
             << L"-" << formatHexPointer(static_cast<std::uintptr_t>(detail.stackBase))
             << L"; detail=" << std::wstring(detail.detail);
        addR0AuditRow(
            rows,
            L"ThreadDetail",
            processId,
            detail.threadId,
            detail.threadObjectAddress,
            detail.processObjectAddress,
            detail.startAddress,
            L"IOCTL_KSWORD_ARK_QUERY_THREAD_DETAIL",
            L"status=" + std::to_wstring(detail.status) + L", last=" + statusHexText(detail.lastStatus),
            100,
            text.str());

        const std::vector<ksword::ark::RuntimeFieldSampleRequestItem> kSampleItems =
            buildThreadRuntimeSampleItems(detail);
        if (!kSampleItems.empty()) {
            const ksword::ark::RuntimeFieldSampleResult kSamples =
                kDriverClient.queryThreadRuntimeFieldSamples(detail.threadId, processId, kSampleItems);
            addR0AuditRow(
                rows,
                L"ThreadRuntimeFields",
                processId,
                detail.threadId,
                kSamples.objectAddress,
                detail.processObjectAddress,
                detail.startAddress,
                L"IOCTL_KSWORD_ARK_QUERY_THREAD_RUNTIME_FIELDS",
                kSamples.io.ok ? L"OK" : (kSamples.unsupported ? L"Unsupported" : L"Unavailable"),
                kSamples.io.ok ? 100UL : 0UL,
                L"returned=" + std::to_wstring(kSamples.returnedCount) +
                    L"/" + std::to_wstring(kSamples.totalCount) +
                    L"; status=" + std::to_wstring(kSamples.status) +
                    L"; " + narrowToWide(kSamples.io.message));
            for (const ksword::ark::RuntimeFieldSampleEntry& sample : kSamples.entries) {
                addR0AuditRow(
                    rows,
                    L"ThreadField",
                    processId,
                    detail.threadId,
                    kSamples.objectAddress,
                    detail.processObjectAddress,
                    detail.startAddress,
                    narrowToWide(sample.name.empty() ? std::string("runtime-field") : sample.name),
                    L"rowStatus=" + std::to_wstring(sample.status),
                    sample.status == KSWORD_ARK_RUNTIME_FIELD_SAMPLE_ROW_STATUS_OK ? 100UL : 50UL,
                    L"id=" + std::to_wstring(sample.runtimeItemId) +
                        L"; offset=" + hexMaskText(sample.offset) +
                        L"; size=" + std::to_wstring(sample.size) +
                        L"; bytesRead=" + std::to_wstring(sample.bytesRead) +
                        L"; value=" + formatHexPointer(static_cast<std::uintptr_t>(sample.valueU64)) +
                        L"; last=" + statusHexText(sample.lastStatus));
            }
        }
    }

    succeededOut = statusOut.empty();
    if (statusOut.empty()) {
        statusOut = L"OK";
    }
    return rows;
}

} // namespace

ProcessDetailSnapshot ProcessDetailCollector::collect(
    DWORD processId,
    ULONGLONG expectedCreationTime100ns) const {
    ProcessDetailSnapshot snapshot{};
    snapshot.basic.processId = processId;
    if (processId == 0 || expectedCreationTime100ns == 0U) {
        snapshot.basic.statusText = L"Process identity is unavailable; detail refresh skipped.";
        snapshot.errorText = L"Basic: " + snapshot.basic.statusText;
        return snapshot;
    }

    const HANDLE kRawIdentityProcess = ::OpenProcess(kProcessBasicAccess, FALSE, processId);
    const DWORD kIdentityOpenError = kRawIdentityProcess ? ERROR_SUCCESS : ::GetLastError();
    ksword::core::UniqueHandle identityProcess(kRawIdentityProcess);
    if (!identityProcess.valid()) {
        snapshot.basic.statusText = win32ErrorText(L"OpenProcess(identity)", kIdentityOpenError);
        snapshot.errorText = L"Basic: " + snapshot.basic.statusText;
        return snapshot;
    }

    FILETIME creationTime{};
    FILETIME exitTime{};
    FILETIME kernelTime{};
    FILETIME userTime{};
    const BOOL kIdentityTimeOk = ::GetProcessTimes(
        identityProcess.get(),
        &creationTime,
        &exitTime,
        &kernelTime,
        &userTime);
    const DWORD kIdentityTimeError = kIdentityTimeOk ? ERROR_SUCCESS : ::GetLastError();
    const ULONGLONG kActualCreationTime100ns = kIdentityTimeOk
        ? (static_cast<ULONGLONG>(creationTime.dwHighDateTime) << 32U) |
            static_cast<ULONGLONG>(creationTime.dwLowDateTime)
        : 0U;
    if (!kIdentityTimeOk || kActualCreationTime100ns == 0U ||
        kActualCreationTime100ns != expectedCreationTime100ns) {
        snapshot.basic.statusText = !kIdentityTimeOk
            ? win32ErrorText(L"GetProcessTimes(identity)", kIdentityTimeError)
            : L"Process identity changed (PID was reused); detail refresh skipped.";
        snapshot.errorText = L"Basic: " + snapshot.basic.statusText;
        return snapshot;
    }

    snapshot.basic = collectBasicInfo(processId, snapshot.basicSucceeded);

    std::wstring threadStatus;
    snapshot.threads = collectThreads(processId, snapshot.threadsSucceeded, threadStatus);
    if (snapshot.threadsSucceeded) {
        const std::size_t kBoundedThreadCount = (std::min)(
            snapshot.threads.size(),
            static_cast<std::size_t>((std::numeric_limits<DWORD>::max)()));
        snapshot.basic.threadCount = static_cast<DWORD>(kBoundedThreadCount);
    }
    if (!snapshot.threadsSucceeded && !threadStatus.empty()) {
        snapshot.errorText += L"Threads: " + threadStatus + L"\r\n";
    }

    std::wstring moduleStatus;
    snapshot.modules = collectModules(processId, snapshot.modulesSucceeded, moduleStatus);
    if (!snapshot.modulesSucceeded && !moduleStatus.empty()) {
        snapshot.errorText += L"Modules: " + moduleStatus + L"\r\n";
    }
    attachRepresentativeThreads(snapshot.modules, snapshot.threads);

    std::wstring r0AuditStatus;
    snapshot.r0AuditRows = collectR0AuditRows(processId, snapshot.r0AuditSucceeded, r0AuditStatus);
    if (!snapshot.r0AuditSucceeded && !r0AuditStatus.empty()) {
        snapshot.errorText += L"R0Audit: " + r0AuditStatus + L"\r\n";
    }

    if (!snapshot.basicSucceeded && !snapshot.basic.statusText.empty()) {
        snapshot.errorText = L"Basic: " + snapshot.basic.statusText + L"\r\n" + snapshot.errorText;
    }
    if (snapshot.errorText.empty()) {
        snapshot.errorText = L"OK";
    }
    return snapshot;
}

} // namespace Ksword::Features::process_detail

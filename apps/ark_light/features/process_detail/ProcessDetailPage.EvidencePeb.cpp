#include "ProcessDetailPage.h"

#include "ProcessDetailCollector.h"

#include "../../ui/ExportUtil.h"

#include <commctrl.h>
#include <psapi.h>
#include <windowsx.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cwchar>
#include <cwctype>
#include <iomanip>
#include <limits>
#include <sstream>
#include <string>
#include <vector>

namespace ksword::features::process_detail {
namespace {

constexpr UINT_PTR kCopySubclassId = 0x4B535745U;
constexpr UINT kCopyTextCommand = 65101U;
constexpr ULONG kProcessBasicInformationClass = 0U;
constexpr ULONG kProcessWow64InformationClass = 26U;
constexpr std::size_t kMaxRemoteUnicodeBytes = 256U * 1024U;
constexpr std::size_t kMaxEnvironmentBytes = 128U * 1024U;
constexpr std::size_t kEnvironmentChunkBytes = 4096U;
constexpr std::size_t kMaxEnvironmentLines = 20U;
constexpr std::uint64_t kMaxRegionCount = 60000U;
constexpr std::uint64_t kMaxPreviewRegions = 40U;

using NtQueryInformationProcessFn = LONG(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);

struct ProcessBasicInformationLite final {
    PVOID reserved1 = nullptr;
    PVOID pebBaseAddress = nullptr;
    PVOID reserved2[2]{};
    ULONG_PTR uniqueProcessId = 0;
    PVOID reserved3 = nullptr;
};

struct RemoteUnicodeString32 final {
    USHORT length = 0;
    USHORT maximumLength = 0;
    std::uint32_t buffer = 0;
};

struct RemoteUnicodeString64 final {
    USHORT length = 0;
    USHORT maximumLength = 0;
    std::uint32_t padding = 0;
    std::uint64_t buffer = 0;
};

struct Curdir32 final {
    RemoteUnicodeString32 dosPath{};
    std::uint32_t handle = 0;
};

struct Curdir64 final {
    RemoteUnicodeString64 dosPath{};
    std::uint64_t handle = 0;
};

struct Peb32Lite final {
    BYTE reserved1[2]{};
    BYTE beingDebugged = 0;
    BYTE reserved2[1]{};
    std::uint32_t mutant = 0;
    std::uint32_t imageBaseAddress = 0;
    std::uint32_t ldr = 0;
    std::uint32_t processParameters = 0;
};

struct Peb64Lite final {
    BYTE reserved1[2]{};
    BYTE beingDebugged = 0;
    BYTE reserved2[1]{};
    std::uint32_t padding = 0;
    std::uint64_t mutant = 0;
    std::uint64_t imageBaseAddress = 0;
    std::uint64_t ldr = 0;
    std::uint64_t processParameters = 0;
};

struct RtlUserProcessParameters32Lite final {
    BYTE reservedBeforeCurrentDirectory[0x24]{};
    Curdir32 currentDirectory{};
    RemoteUnicodeString32 dllPath{};
    RemoteUnicodeString32 imagePathName{};
    RemoteUnicodeString32 commandLine{};
    std::uint32_t environment = 0;
};

struct RtlUserProcessParameters64Lite final {
    BYTE reservedBeforeCurrentDirectory[0x38]{};
    Curdir64 currentDirectory{};
    RemoteUnicodeString64 dllPath{};
    RemoteUnicodeString64 imagePathName{};
    RemoteUnicodeString64 commandLine{};
    std::uint64_t environment = 0;
};

static_assert(offsetof(Peb32Lite, imageBaseAddress) == 0x08);
static_assert(offsetof(Peb32Lite, processParameters) == 0x10);
static_assert(offsetof(Peb64Lite, imageBaseAddress) == 0x10);
static_assert(offsetof(Peb64Lite, processParameters) == 0x20);
static_assert(offsetof(RtlUserProcessParameters32Lite, currentDirectory) == 0x24);
static_assert(offsetof(RtlUserProcessParameters32Lite, imagePathName) == 0x38);
static_assert(offsetof(RtlUserProcessParameters32Lite, commandLine) == 0x40);
static_assert(offsetof(RtlUserProcessParameters32Lite, environment) == 0x48);
static_assert(offsetof(RtlUserProcessParameters64Lite, currentDirectory) == 0x38);
static_assert(offsetof(RtlUserProcessParameters64Lite, imagePathName) == 0x60);
static_assert(offsetof(RtlUserProcessParameters64Lite, commandLine) == 0x70);
static_assert(offsetof(RtlUserProcessParameters64Lite, environment) == 0x80);

struct PebReadResult final {
    std::wstring name;
    bool ok = false;
    bool wow64 = false;
    bool beingDebugged = false;
    std::uint64_t pebAddress = 0;
    std::uint64_t imageBaseAddress = 0;
    std::uint64_t processParametersAddress = 0;
    std::uint64_t environmentAddress = 0;
    std::wstring commandLine;
    std::wstring imagePath;
    std::wstring currentDirectory;
    std::wstring diagnostic;
};

std::wstring formatHex(const std::uint64_t value) {
    std::wostringstream text;
    text << L"0x" << std::hex << std::uppercase << value;
    return text.str();
}

std::wstring formatByteHex(const std::uint64_t value) {
    std::wostringstream text;
    text << L"0x" << std::hex << std::uppercase << std::setw(2) << std::setfill(L'0') << (value & 0xFFU);
    return text.str();
}

std::wstring trimCopy(std::wstring text) {
    const auto kIsSpace = [](const wchar_t value) { return std::iswspace(value) != 0; };
    text.erase(text.begin(), std::find_if_not(text.begin(), text.end(), kIsSpace));
    text.erase(std::find_if_not(text.rbegin(), text.rend(), kIsSpace).base(), text.end());
    return text;
}

std::wstring extractDetailValue(const std::wstring& detail, const std::wstring& key) {
    const std::wstring kMarker = key + L"=";
    const std::size_t kBegin = detail.find(kMarker);
    if (kBegin == std::wstring::npos) {
        return {};
    }
    const std::size_t kValueBegin = kBegin + kMarker.size();
    const std::size_t kEnd = detail.find(L';', kValueBegin);
    return trimCopy(detail.substr(kValueBegin, kEnd == std::wstring::npos ? std::wstring::npos : kEnd - kValueBegin));
}

const ProcessR0AuditInfo* findAuditScope(
    const std::vector<ProcessR0AuditInfo>& rows,
    const wchar_t* scope) {
    const auto kFound = std::find_if(rows.begin(), rows.end(), [scope](const ProcessR0AuditInfo& row) {
        return row.scope == scope;
    });
    return kFound == rows.end() ? nullptr : &*kFound;
}

const ProcessR0AuditInfo* findAuditSource(
    const std::vector<ProcessR0AuditInfo>& rows,
    const wchar_t* source) {
    const auto kFound = std::find_if(rows.begin(), rows.end(), [source](const ProcessR0AuditInfo& row) {
        return row.scope == L"ProcessField" && row.sourceText == source;
    });
    return kFound == rows.end() ? nullptr : &*kFound;
}

bool copyWindowTextToClipboard(HWND window) {
    if (!window) {
        return false;
    }
    const int kLength = ::GetWindowTextLengthW(window);
    if (kLength <= 0) {
        return false;
    }
    std::wstring text(static_cast<std::size_t>(kLength) + 1U, L'\0');
    ::GetWindowTextW(window, text.data(), static_cast<int>(text.size()));
    text.resize(std::wcslen(text.c_str()));
    return ksword::ui::copyTextToClipboard(window, text, L"进程 PEB 证据");
}

LRESULT CALLBACK copyableTextSubclassProc(
    HWND hwnd,
    UINT message,
    WPARAM wParam,
    LPARAM lParam,
    UINT_PTR subclassId,
    DWORD_PTR) {
    if (message == WM_CONTEXTMENU) {
        POINT point{ GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam) };
        if (point.x == -1 && point.y == -1) {
            RECT bounds{};
            ::GetWindowRect(hwnd, &bounds);
            point = { bounds.left + 16, bounds.top + 16 };
        }
        HMENU menu = ::CreatePopupMenu();
        ::AppendMenuW(menu, MF_STRING, kCopyTextCommand, L"复制");
        const UINT kCommand = ::TrackPopupMenu(
            menu,
            TPM_RETURNCMD | TPM_RIGHTBUTTON,
            point.x,
            point.y,
            0,
            hwnd,
            nullptr);
        ::DestroyMenu(menu);
        if (kCommand == kCopyTextCommand) {
            copyWindowTextToClipboard(hwnd);
        }
        return 0;
    }
    if (message == WM_NCDESTROY) {
        ::RemoveWindowSubclass(hwnd, copyableTextSubclassProc, subclassId);
    }
    return ::DefSubclassProc(hwnd, message, wParam, lParam);
}

void makeCopyable(HWND control) {
    if (control) {
        ::SetWindowSubclass(control, copyableTextSubclassProc, kCopySubclassId, 0);
    }
}

bool readRemoteExact(
    HANDLE process,
    const std::uint64_t address,
    void* buffer,
    const SIZE_T bufferSize) {
    if (!process || address == 0 || !buffer || bufferSize == 0) {
        return false;
    }
    SIZE_T bytesRead = 0;
    return ::ReadProcessMemory(
               process,
               reinterpret_cast<LPCVOID>(static_cast<std::uintptr_t>(address)),
               buffer,
               bufferSize,
               &bytesRead) != FALSE &&
        bytesRead == bufferSize;
}

template <typename T>
bool readRemoteStructure(HANDLE process, const std::uint64_t address, T& value) {
    value = {};
    return readRemoteExact(process, address, &value, sizeof(value));
}

std::wstring readRemoteUnicode(
    HANDLE process,
    const std::uint64_t address,
    const USHORT byteLength) {
    if (!process || address == 0 || byteLength == 0 ||
        (byteLength % sizeof(wchar_t)) != 0 || byteLength > kMaxRemoteUnicodeBytes) {
        return {};
    }
    std::vector<wchar_t> buffer(static_cast<std::size_t>(byteLength / sizeof(wchar_t)) + 1U, L'\0');
    SIZE_T bytesRead = 0;
    if (::ReadProcessMemory(
            process,
            reinterpret_cast<LPCVOID>(static_cast<std::uintptr_t>(address)),
            buffer.data(),
            byteLength,
            &bytesRead) == FALSE ||
        bytesRead == 0) {
        return {};
    }
    buffer[std::min<std::size_t>(buffer.size() - 1U, bytesRead / sizeof(wchar_t))] = L'\0';
    return std::wstring(buffer.data(), bytesRead / sizeof(wchar_t));
}

PebReadResult readPeb64(HANDLE process, const std::uint64_t pebAddress) {
    PebReadResult result{};
    result.name = L"NativePEB";
    result.pebAddress = pebAddress;
    Peb64Lite peb{};
    if (!readRemoteStructure(process, pebAddress, peb)) {
        result.diagnostic = L"读取64位PEB头失败。";
        return result;
    }
    result.beingDebugged = peb.beingDebugged != 0;
    result.imageBaseAddress = peb.imageBaseAddress;
    result.processParametersAddress = peb.processParameters;
    if (peb.processParameters == 0) {
        result.diagnostic = L"NativePEB.ProcessParameters为空。";
        return result;
    }
    RtlUserProcessParameters64Lite parameters{};
    if (!readRemoteStructure(process, peb.processParameters, parameters)) {
        result.diagnostic = L"读取64位RTL_USER_PROCESS_PARAMETERS失败。";
        return result;
    }
    result.environmentAddress = parameters.environment;
    result.commandLine = readRemoteUnicode(process, parameters.commandLine.buffer, parameters.commandLine.length);
    result.imagePath = readRemoteUnicode(process, parameters.imagePathName.buffer, parameters.imagePathName.length);
    result.currentDirectory = readRemoteUnicode(
        process,
        parameters.currentDirectory.dosPath.buffer,
        parameters.currentDirectory.dosPath.length);
    result.ok = true;
    return result;
}

PebReadResult readPeb32(HANDLE process, const std::uint64_t pebAddress) {
    PebReadResult result{};
    result.name = L"Wow64PEB";
    result.wow64 = true;
    result.pebAddress = pebAddress;
    Peb32Lite peb{};
    if (!readRemoteStructure(process, pebAddress, peb)) {
        result.diagnostic = L"读取32位PEB头失败。";
        return result;
    }
    result.beingDebugged = peb.beingDebugged != 0;
    result.imageBaseAddress = peb.imageBaseAddress;
    result.processParametersAddress = peb.processParameters;
    if (peb.processParameters == 0) {
        result.diagnostic = L"Wow64PEB.ProcessParameters为空。";
        return result;
    }
    RtlUserProcessParameters32Lite parameters{};
    if (!readRemoteStructure(process, peb.processParameters, parameters)) {
        result.diagnostic = L"读取32位RTL_USER_PROCESS_PARAMETERS失败。";
        return result;
    }
    result.environmentAddress = parameters.environment;
    result.commandLine = readRemoteUnicode(process, parameters.commandLine.buffer, parameters.commandLine.length);
    result.imagePath = readRemoteUnicode(process, parameters.imagePathName.buffer, parameters.imagePathName.length);
    result.currentDirectory = readRemoteUnicode(
        process,
        parameters.currentDirectory.dosPath.buffer,
        parameters.currentDirectory.dosPath.length);
    result.ok = true;
    return result;
}

std::vector<std::wstring> readEnvironmentPreview(
    HANDLE process,
    const std::uint64_t address,
    std::wstring& diagnostic) {
    std::vector<std::wstring> lines;
    if (!process || address == 0) {
        return lines;
    }
    std::vector<wchar_t> allChars;
    bool doubleNullFound = false;
    std::size_t byteOffset = 0;
    while (byteOffset < kMaxEnvironmentBytes && !doubleNullFound) {
        const std::size_t kRequestBytes = std::min(kEnvironmentChunkBytes, kMaxEnvironmentBytes - byteOffset);
        std::vector<std::uint8_t> bytes(kRequestBytes, 0U);
        SIZE_T bytesRead = 0;
        if (::ReadProcessMemory(
                process,
                reinterpret_cast<LPCVOID>(static_cast<std::uintptr_t>(address + byteOffset)),
                bytes.data(),
                kRequestBytes,
                &bytesRead) == FALSE ||
            bytesRead < sizeof(wchar_t)) {
            diagnostic = L"环境块读取在 offset=" + std::to_wstring(byteOffset) + L" 处停止。";
            break;
        }
        const std::size_t kCharCount = bytesRead / sizeof(wchar_t);
        const auto* chars = reinterpret_cast<const wchar_t*>(bytes.data());
        const std::size_t kPreviousSize = allChars.size();
        allChars.insert(allChars.end(), chars, chars + kCharCount);
        const std::size_t kScanBegin = kPreviousSize == 0 ? 1U : kPreviousSize;
        for (std::size_t index = kScanBegin; index < allChars.size(); ++index) {
            if (allChars[index - 1U] == L'\0' && allChars[index] == L'\0') {
                allChars.resize(index + 1U);
                doubleNullFound = true;
                break;
            }
        }
        byteOffset += kCharCount * sizeof(wchar_t);
    }
    if (!doubleNullFound && diagnostic.empty()) {
        diagnostic = L"环境块超过128KB或缺少双NUL终止。";
    }
    std::size_t cursor = 0;
    while (cursor < allChars.size() && lines.size() < kMaxEnvironmentLines) {
        std::size_t length = 0;
        while (cursor + length < allChars.size() && allChars[cursor + length] != L'\0') {
            ++length;
        }
        if (length == 0) {
            break;
        }
        lines.emplace_back(allChars.data() + cursor, length);
        cursor += length + 1U;
    }
    return lines;
}

std::wstring priorityClassText(const DWORD priorityClass) {
    switch (priorityClass) {
    case IDLE_PRIORITY_CLASS: return L"IDLE";
    case BELOW_NORMAL_PRIORITY_CLASS: return L"BELOW_NORMAL";
    case NORMAL_PRIORITY_CLASS: return L"NORMAL";
    case ABOVE_NORMAL_PRIORITY_CLASS: return L"ABOVE_NORMAL";
    case HIGH_PRIORITY_CLASS: return L"HIGH";
    case REALTIME_PRIORITY_CLASS: return L"REALTIME";
    default: return L"UNKNOWN(" + std::to_wstring(priorityClass) + L")";
    }
}

DWORD priorityClassByComboIndex(const int index) {
    constexpr std::array<DWORD, 7> kValues{
        0,
        IDLE_PRIORITY_CLASS,
        BELOW_NORMAL_PRIORITY_CLASS,
        NORMAL_PRIORITY_CLASS,
        ABOVE_NORMAL_PRIORITY_CLASS,
        HIGH_PRIORITY_CLASS,
        REALTIME_PRIORITY_CLASS
    };
    return index >= 0 && index < static_cast<int>(kValues.size()) ? kValues[static_cast<std::size_t>(index)] : 0;
}

int comboIndexByPriorityClass(const DWORD priorityClass) {
    for (int index = 1; index <= 6; ++index) {
        if (priorityClassByComboIndex(index) == priorityClass) {
            return index;
        }
    }
    return 0;
}

bool parseUnsigned(const std::wstring& source, std::uint64_t& value) {
    std::wstring text = trimCopy(source);
    if (text.empty()) {
        return false;
    }
    int base = 10;
    if (text.size() > 2 && text[0] == L'0' && (text[1] == L'x' || text[1] == L'X')) {
        text.erase(0, 2);
        base = 16;
    }
    wchar_t* end = nullptr;
    errno = 0;
    const unsigned long long kParsed = std::wcstoull(text.c_str(), &end, base);
    if (errno != 0 || !end || *end != L'\0') {
        return false;
    }
    value = kParsed;
    return true;
}

std::wstring memoryStateText(const DWORD state) {
    switch (state) {
    case MEM_COMMIT: return L"Commit";
    case MEM_RESERVE: return L"Reserve";
    case MEM_FREE: return L"Free";
    default: return formatHex(state);
    }
}

std::wstring memoryTypeText(const DWORD type) {
    switch (type) {
    case MEM_IMAGE: return L"Image";
    case MEM_MAPPED: return L"Mapped";
    case MEM_PRIVATE: return L"Private";
    default: return formatHex(type);
    }
}

std::wstring memoryProtectText(const DWORD protect) {
    if (protect == 0) {
        return L"-";
    }
    std::wstring text;
    switch (protect & 0xFFU) {
    case PAGE_NOACCESS: text = L"NOACCESS"; break;
    case PAGE_READONLY: text = L"R"; break;
    case PAGE_READWRITE: text = L"RW"; break;
    case PAGE_WRITECOPY: text = L"WC"; break;
    case PAGE_EXECUTE: text = L"X"; break;
    case PAGE_EXECUTE_READ: text = L"XR"; break;
    case PAGE_EXECUTE_READWRITE: text = L"XRW"; break;
    case PAGE_EXECUTE_WRITECOPY: text = L"XWC"; break;
    default: text = formatHex(protect & 0xFFU); break;
    }
    if ((protect & PAGE_GUARD) != 0) { text += L"|GUARD"; }
    if ((protect & PAGE_NOCACHE) != 0) { text += L"|NOCACHE"; }
    if ((protect & PAGE_WRITECOMBINE) != 0) { text += L"|WRITECOMBINE"; }
    return text;
}

// collectPebSnapshot owns all remote-memory reads and address-space enumeration
// performed by the PEB page. It receives only immutable request inputs and
// returns strings/values that can safely be applied after the worker finishes.
ProcessPebSnapshot collectPebSnapshot(
    const DWORD processId,
    const ULONGLONG expectedProcessCreationTime100ns,
    const int selectedTarget) {
    ProcessPebSnapshot snapshot{};
    const auto kBegin = std::chrono::steady_clock::now();
    std::wostringstream report;
    report << L"[PEB / Process Summary]\r\n";
    report << L"PID: " << processId << L"\r\n";
    std::vector<std::wstring> diagnostics;
    std::vector<PebReadResult> pebResults;

    if (processId == 0U || expectedProcessCreationTime100ns == 0U) {
        report << L"ProcessIdentity: <unavailable>\r\n";
        snapshot.completed = true;
        snapshot.reportText = report.str();
        snapshot.statusText = L"● PEB 刷新已取消 | 进程身份不可用";
        return snapshot;
    }

    HANDLE process = ::OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
        FALSE,
        processId);
    if (!process) {
        process = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
    }
    if (process) {
        FILETIME creationTime{};
        FILETIME exitTime{};
        FILETIME kernelTime{};
        FILETIME userTime{};
        if (!::GetProcessTimes(process, &creationTime, &exitTime, &kernelTime, &userTime)) {
            const DWORD kIdentityError = ::GetLastError();
            report << L"ProcessIdentity: <GetProcessTimes failed>\r\n";
            diagnostics.push_back(L"GetProcessTimes(identity)失败(" + std::to_wstring(kIdentityError) + L")");
            ::CloseHandle(process);
            snapshot.completed = true;
            snapshot.reportText = report.str();
            snapshot.statusText = L"● PEB 刷新已取消 | 无法验证进程身份";
            return snapshot;
        }
        const ULONGLONG kActualProcessCreationTime100ns =
            (static_cast<ULONGLONG>(creationTime.dwHighDateTime) << 32U) |
            static_cast<ULONGLONG>(creationTime.dwLowDateTime);
        if (kActualProcessCreationTime100ns == 0U ||
            kActualProcessCreationTime100ns != expectedProcessCreationTime100ns) {
            report << L"ProcessIdentity: <changed>\r\n";
            diagnostics.push_back(L"目标进程实例已变更（PID 已复用），PEB 刷新被取消。");
            ::CloseHandle(process);
            snapshot.completed = true;
            snapshot.reportText = report.str();
            snapshot.statusText = L"● PEB 刷新已取消 | 目标进程实例已变更";
            return snapshot;
        }
        snapshot.identityMatched = true;
    }
    if (!process) {
        diagnostics.push_back(L"OpenProcess失败(" + std::to_wstring(::GetLastError()) + L")");
        report << L"OpenProcess: <failed>\r\n";
    } else {
        HMODULE ntdll = ::GetModuleHandleW(L"ntdll.dll");
        const auto kNtQuery = reinterpret_cast<NtQueryInformationProcessFn>(
            ntdll ? ::GetProcAddress(ntdll, "NtQueryInformationProcess") : nullptr);
        ProcessBasicInformationLite basic{};
        if (kNtQuery) {
            const LONG kStatus = kNtQuery(process, kProcessBasicInformationClass, &basic, sizeof(basic), nullptr);
            if (kStatus >= 0 && basic.pebBaseAddress) {
                report << L"PEB Address: " << formatHex(reinterpret_cast<std::uint64_t>(basic.pebBaseAddress)) << L"\r\n";
                pebResults.push_back(readPeb64(process, reinterpret_cast<std::uint64_t>(basic.pebBaseAddress)));
            } else {
                diagnostics.push_back(L"ProcessBasicInformation未返回可用PEB地址。");
            }
            ULONG_PTR wow64Peb = 0;
            const LONG kWowStatus = kNtQuery(process, kProcessWow64InformationClass, &wow64Peb, sizeof(wow64Peb), nullptr);
            if (kWowStatus >= 0 && wow64Peb != 0 && wow64Peb != reinterpret_cast<ULONG_PTR>(basic.pebBaseAddress)) {
                pebResults.push_back(readPeb32(process, static_cast<std::uint64_t>(wow64Peb)));
            }
        } else {
            diagnostics.push_back(L"NtQueryInformationProcess不可用。");
        }

        ULONG_PTR processAffinity = 0;
        ULONG_PTR systemAffinity = 0;
        if (::GetProcessAffinityMask(process, &processAffinity, &systemAffinity)) {
            report << L"ProcessAffinity: " << formatHex(processAffinity) << L"\r\n";
            report << L"CpuCoreAffinity: ";
            bool first = true;
            for (unsigned int bit = 0; bit < sizeof(ULONG_PTR) * 8U; ++bit) {
                if ((processAffinity & (static_cast<ULONG_PTR>(1) << bit)) == 0) { continue; }
                if (!first) { report << L","; }
                report << bit;
                first = false;
            }
            report << L"\r\n";
            snapshot.affinityKnown = true;
            snapshot.affinityText = formatHex(processAffinity);
        }

        const DWORD kPriorityClass = ::GetPriorityClass(process);
        report << L"PriorityClass: " << priorityClassText(kPriorityClass) << L"\r\n";
        snapshot.priorityKnown = kPriorityClass != 0;
        snapshot.priorityComboIndex = comboIndexByPriorityClass(kPriorityClass);

        USHORT processMachine = IMAGE_FILE_MACHINE_UNKNOWN;
        USHORT nativeMachine = IMAGE_FILE_MACHINE_UNKNOWN;
        if (::IsWow64Process2(process, &processMachine, &nativeMachine)) {
            report << L"Wow64ProcessMachine: " << formatHex(processMachine) << L"\r\n";
            report << L"Wow64NativeMachine: " << formatHex(nativeMachine) << L"\r\n";
        }

        FILETIME creationTime{}, exitTime{}, kernelTime{}, userTime{};
        if (::GetProcessTimes(process, &creationTime, &exitTime, &kernelTime, &userTime)) {
            ULARGE_INTEGER kernel{};
            kernel.LowPart = kernelTime.dwLowDateTime;
            kernel.HighPart = kernelTime.dwHighDateTime;
            ULARGE_INTEGER user{};
            user.LowPart = userTime.dwLowDateTime;
            user.HighPart = userTime.dwHighDateTime;
            report << L"KernelCpuMs: " << static_cast<double>(kernel.QuadPart) / 10000.0 << L"\r\n";
            report << L"UserCpuMs: " << static_cast<double>(user.QuadPart) / 10000.0 << L"\r\n";
        }

        PROCESS_MEMORY_COUNTERS_EX memoryCounters{};
        if (::GetProcessMemoryInfo(
                process,
                reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&memoryCounters),
                sizeof(memoryCounters))) {
            report << L"WorkingSet: " << memoryCounters.WorkingSetSize << L" bytes\r\n";
            report << L"PrivateUsage: " << memoryCounters.PrivateUsage << L" bytes\r\n";
            report << L"PeakWorkingSet: " << memoryCounters.PeakWorkingSetSize << L" bytes\r\n";
            report << L"QuotaPagedPool: " << memoryCounters.QuotaPagedPoolUsage << L" bytes\r\n";
            report << L"QuotaNonPagedPool: " << memoryCounters.QuotaNonPagedPoolUsage << L" bytes\r\n";
            report << L"PageFaultCount: " << memoryCounters.PageFaultCount << L"\r\n";
        }

        IO_COUNTERS io{};
        if (::GetProcessIoCounters(process, &io)) {
            report << L"ReadOps: " << io.ReadOperationCount << L"\r\n";
            report << L"WriteOps: " << io.WriteOperationCount << L"\r\n";
            report << L"ReadBytes: " << io.ReadTransferCount << L"\r\n";
            report << L"WriteBytes: " << io.WriteTransferCount << L"\r\n";
        }

        for (PebReadResult& peb : pebResults) {
            if (!peb.ok) {
                diagnostics.push_back(peb.name + L": " + peb.diagnostic);
                continue;
            }
            report << L"[" << peb.name << L"]\r\n";
            report << L"  PebAddress: " << formatHex(peb.pebAddress) << L"\r\n";
            report << L"  ProcessParameters: " << formatHex(peb.processParametersAddress) << L"\r\n";
            report << L"  ImageBaseAddress: " << formatHex(peb.imageBaseAddress) << L"\r\n";
            report << L"  Environment: " << formatHex(peb.environmentAddress) << L"\r\n";
            report << L"  BeingDebugged: " << (peb.beingDebugged ? L"true" : L"false") << L"\r\n";
            if (!peb.commandLine.empty()) { report << L"CommandLine(" << peb.name << L"): " << peb.commandLine << L"\r\n"; }
            if (!peb.imagePath.empty()) { report << L"ImagePath(" << peb.name << L"): " << peb.imagePath << L"\r\n"; }
            if (!peb.currentDirectory.empty()) { report << L"CurrentDirectory(" << peb.name << L"): " << peb.currentDirectory << L"\r\n"; }
        }

        const wchar_t* targetName = selectedTarget == 1 ? L"Wow64PEB" : L"NativePEB";
        const auto kSelectedPeb = std::find_if(pebResults.begin(), pebResults.end(), [targetName](const PebReadResult& peb) {
            return peb.ok && peb.name == targetName;
        });
        if (kSelectedPeb != pebResults.end()) {
            snapshot.selectedPebKnown = true;
            snapshot.commandLine = kSelectedPeb->commandLine;
            snapshot.imagePath = kSelectedPeb->imagePath;
            snapshot.currentDirectory = kSelectedPeb->currentDirectory;
            snapshot.imageBase = formatHex(kSelectedPeb->imageBaseAddress);

            if (kSelectedPeb->imageBaseAddress != 0) {
                IMAGE_DOS_HEADER dos{};
                if (readRemoteStructure(process, kSelectedPeb->imageBaseAddress, dos) &&
                    dos.e_magic == IMAGE_DOS_SIGNATURE && dos.e_lfanew > 0 && dos.e_lfanew < 0x100000) {
                    IMAGE_NT_HEADERS64 nt{};
                    if (readRemoteStructure(process, kSelectedPeb->imageBaseAddress + dos.e_lfanew, nt) &&
                        nt.Signature == IMAGE_NT_SIGNATURE) {
                        report << L"ImageBaseAddress: " << formatHex(kSelectedPeb->imageBaseAddress) << L"\r\n";
                        report << L"EntryPointRva: " << formatHex(nt.OptionalHeader.AddressOfEntryPoint) << L"\r\n";
                        report << L"EntryPointAddress: "
                               << formatHex(kSelectedPeb->imageBaseAddress + nt.OptionalHeader.AddressOfEntryPoint)
                               << L"\r\n";
                    }
                }
            }
        }

        const auto kEnvironmentPeb = std::find_if(pebResults.begin(), pebResults.end(), [](const PebReadResult& peb) {
            return peb.ok && peb.environmentAddress != 0;
        });
        report << L"[EnvironmentPreview";
        if (kEnvironmentPeb != pebResults.end()) { report << L":" << kEnvironmentPeb->name; }
        report << L"]\r\n";
        if (kEnvironmentPeb != pebResults.end()) {
            std::wstring environmentDiagnostic;
            const std::vector<std::wstring> kEnvironment = readEnvironmentPreview(
                process,
                kEnvironmentPeb->environmentAddress,
                environmentDiagnostic);
            for (const std::wstring& line : kEnvironment) {
                report << L"  " << line << L"\r\n";
            }
            if (kEnvironment.empty()) { report << L"  <unavailable>\r\n"; }
            if (!environmentDiagnostic.empty()) { diagnostics.push_back(environmentDiagnostic); }
        } else {
            report << L"  <unavailable>\r\n";
        }

        SYSTEM_INFO systemInfo{};
        ::GetSystemInfo(&systemInfo);
        std::uintptr_t cursor = reinterpret_cast<std::uintptr_t>(systemInfo.lpMinimumApplicationAddress);
        const std::uintptr_t kMaximum = reinterpret_cast<std::uintptr_t>(systemInfo.lpMaximumApplicationAddress);
        std::uint64_t regionCount = 0;
        std::uint64_t previewCount = 0;
        std::uint64_t commitBytes = 0;
        std::uint64_t mappedBytes = 0;
        std::uint64_t imageBytes = 0;
        std::uint64_t privateBytes = 0;
        const auto kDeadline = kBegin + std::chrono::seconds(8);
        report << L"[VirtualAddressRegionPreview]\r\n";
        while (cursor < kMaximum && regionCount < kMaxRegionCount && std::chrono::steady_clock::now() <= kDeadline) {
            MEMORY_BASIC_INFORMATION info{};
            if (::VirtualQueryEx(process, reinterpret_cast<LPCVOID>(cursor), &info, sizeof(info)) == 0 || info.RegionSize == 0) {
                break;
            }
            ++regionCount;
            if (info.State == MEM_COMMIT) { commitBytes += info.RegionSize; }
            if (info.Type == MEM_MAPPED) { mappedBytes += info.RegionSize; }
            if (info.Type == MEM_IMAGE) { imageBytes += info.RegionSize; }
            if (info.Type == MEM_PRIVATE) { privateBytes += info.RegionSize; }
            if (info.State == MEM_COMMIT && previewCount < kMaxPreviewRegions) {
                const std::uint64_t kStart = reinterpret_cast<std::uint64_t>(info.BaseAddress);
                report << L"  " << formatHex(kStart) << L"-" << formatHex(kStart + info.RegionSize)
                       << L" | " << memoryStateText(info.State)
                       << L" | " << memoryProtectText(info.Protect)
                       << L" | " << memoryTypeText(info.Type);
                if (info.Type == MEM_MAPPED || info.Type == MEM_IMAGE) {
                    wchar_t mappedPath[1024]{};
                    if (::GetMappedFileNameW(process, info.BaseAddress, mappedPath, static_cast<DWORD>(std::size(mappedPath))) > 0) {
                        report << L" | " << mappedPath;
                    }
                }
                report << L"\r\n";
                ++previewCount;
            }
            const std::uintptr_t kNext = cursor + info.RegionSize;
            if (kNext <= cursor) { break; }
            cursor = kNext;
        }
        if (regionCount >= kMaxRegionCount) { diagnostics.push_back(L"虚拟内存枚举达到60000行上限。"); }
        if (std::chrono::steady_clock::now() > kDeadline) { diagnostics.push_back(L"虚拟内存枚举超过8秒，已返回部分结果。"); }
        report << L"RegionCount: " << regionCount << L"\r\n";
        report << L"CommitBytes: " << commitBytes << L"\r\n";
        report << L"MappedBytes: " << mappedBytes << L"\r\n";
        report << L"ImageBytes: " << imageBytes << L"\r\n";
        report << L"PrivateBytes: " << privateBytes << L"\r\n";
        report << L"HeapCount: <skipped>\r\n";
        report << L"HeapBlockCount: <skipped>\r\n";
        report << L"HeapBlockEnumeration: <skipped to keep PEB refresh bounded>\r\n";
        ::CloseHandle(process);
    }

    if (!diagnostics.empty()) {
        report << L"[Diagnostic]\r\n";
        for (const std::wstring& diagnostic : diagnostics) {
            report << L"  " << diagnostic << L"\r\n";
        }
    }
    const auto kElapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - kBegin).count();
    snapshot.completed = true;
    snapshot.reportText = report.str();
    snapshot.statusText =
        L"● 后台刷新完成 " + std::to_wstring(kElapsed) + L" ms" +
        (diagnostics.empty() ? L"" : L" | 存在降级/诊断信息");
    return snapshot;
}

} // namespace

bool ProcessDetailPage::createEvidenceTab() {
    constexpr TabIndex kPage = TabIndex::kEvidence;
    const auto kAddFormRow = [this](const wchar_t* label, const int valueId, const int y) {
        addLabel(TabIndex::kEvidence, 0, label, 20, y, 150, 20);
        makeCopyable(addLabel(TabIndex::kEvidence, valueId, L"Unavailable", 180, y, -14, 20));
    };
    addLabel(kPage, 0, L"查看当前进程的内核对象、字段状态和内存映射信息。", 8, 6, -8, 24);

    addGroup(kPage, L"R0 扩展摘要", 8, 34, -8, 82);
    kAddFormRow(L"R0 状态", kEvidenceR0Status, 52);
    kAddFormRow(L"DynData Capability", kEvidenceCapability, 74);
    kAddFormRow(L"R0 镜像路径", kEvidenceImagePath, 96);

    addGroup(kPage, L"对象字段可用性", 8, 122, -8, 62);
    kAddFormRow(L"HandleTable", kEvidenceHandleTable, 142);
    kAddFormRow(L"SectionObject", kEvidenceSectionObject, 162);

    addGroup(kPage, L"保护与签名字段", 8, 190, -8, 78);
    kAddFormRow(L"EPROCESS.Protection", kEvidenceProtection, 208);
    kAddFormRow(L"SignatureLevel", kEvidenceSignature, 228);
    kAddFormRow(L"SectionSignatureLevel", kEvidenceSectionSignature, 248);

    addGroup(kPage, L"字段来源", 8, 274, -8, 148);
    kAddFormRow(L"Session", kEvidenceSessionSource, 292);
    kAddFormRow(L"ImagePath", kEvidenceImagePathSource, 310);
    kAddFormRow(L"Protection", kEvidenceProtectionSource, 328);
    kAddFormRow(L"SignatureLevel", kEvidenceSignatureSource, 346);
    kAddFormRow(L"SectionSignatureLevel", kEvidenceSectionSignatureSource, 364);
    kAddFormRow(L"ObjectTable", kEvidenceObjectTableSource, 382);
    kAddFormRow(L"SectionObject", kEvidenceSectionObjectSource, 400);

    addGroup(kPage, L"EPROCESS 偏移", 8, 428, -8, 112);
    kAddFormRow(L"Protection", kEvidenceProtectionOffset, 446);
    kAddFormRow(L"SignatureLevel", kEvidenceSignatureOffset, 464);
    kAddFormRow(L"SectionSignatureLevel", kEvidenceSectionSignatureOffset, 482);
    kAddFormRow(L"ObjectTable", kEvidenceObjectTableOffset, 500);
    kAddFormRow(L"SectionObject", kEvidenceSectionObjectOffset, 518);

    addGroup(kPage, L"Section / ControlArea 映射关系", 8, 546, -8, -8);
    addButton(kPage, kEvidenceRefreshSection, L"刷新 Section", 20, 566, 116, 28);
    makeCopyable(addLabel(kPage, kEvidenceSectionStatus, L"● 尚未刷新", 146, 566, -16, 28));
    addEdit(
        kPage,
        kEvidenceSectionOutput,
        L"Section/ControlArea 查询结果将在此处显示。",
        true,
        true,
        20,
        602,
        -16,
        -18);
    return true;
}

bool ProcessDetailPage::createPebTab() {
    constexpr TabIndex kPage = TabIndex::kPeb;
    addButton(kPage, kPebRefresh, L"刷新PEB", 8, 8, 92, 30);
    addButton(kPage, kPebApply, L"应用修改", 108, 8, 96, 30);
    makeCopyable(addLabel(kPage, kPebStatus, L"● 尚未刷新", 214, 8, -8, 30));

    addGroup(kPage, L"PEB 可编辑字段（R3 写入目标进程内存）", 8, 44, -8, 230);
    addLabel(kPage, 0, L"目标PEB", 20, 64, 124, 24);
    HWND target = addCombo(kPage, kPebTarget, 150, 62, 180, 240);
    if (target) {
        ::SendMessageW(target, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"NativePEB"));
        ::SendMessageW(target, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"Wow64PEB"));
        ::SendMessageW(target, CB_SETCURSEL, 0, 0);
        makeCopyable(target);
    }

    addLabel(kPage, 0, L"CommandLine", 20, 94, 124, 24);
    addEdit(kPage, kPebCommandLine, L"", false, false, 150, 92, -16, 26);
    addLabel(kPage, 0, L"ImagePathName", 20, 124, 124, 24);
    addEdit(kPage, kPebImagePath, L"", false, false, 150, 122, -16, 26);
    addLabel(kPage, 0, L"CurrentDirectory", 20, 154, 124, 24);
    addEdit(kPage, kPebCurrentDirectory, L"", false, false, 150, 152, -16, 26);

    addLabel(kPage, 0, L"环境变量名", 20, 184, 124, 24);
    addEdit(kPage, kPebEnvironmentName, L"", false, false, 150, 182, 260, 26);
    addLabel(kPage, 0, L"环境变量值", 424, 184, 110, 24);
    addEdit(kPage, kPebEnvironmentValue, L"", false, false, 540, 182, -16, 26);

    addLabel(kPage, 0, L"ImageBaseAddress", 20, 214, 124, 24);
    addEdit(kPage, kPebImageBase, L"", false, false, 150, 212, 260, 26);
    addLabel(kPage, 0, L"AffinityMask", 424, 214, 110, 24);
    addEdit(kPage, kPebAffinity, L"", false, false, 540, 212, -16, 26);

    addLabel(kPage, 0, L"PriorityClass", 20, 244, 124, 24);
    HWND priority = addCombo(kPage, kPebPriority, 150, 242, 260, 220);
    if (priority) {
        constexpr std::array<const wchar_t*, 7> kPriorities{
            L"不修改", L"IDLE", L"BELOW_NORMAL", L"NORMAL", L"ABOVE_NORMAL", L"HIGH", L"REALTIME"
        };
        for (const wchar_t* item : kPriorities) {
            ::SendMessageW(priority, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(item));
        }
        ::SendMessageW(priority, CB_SETCURSEL, 0, 0);
        makeCopyable(priority);
    }

    addEdit(
        kPage,
        kPebOutput,
        L"PEB 与地址空间摘要将在此处显示。",
        true,
        true,
        8,
        282,
        -8,
        252);
    addEdit(
        kPage,
        kPebReadonlyReason,
        L"不可直接修改/不建议直接修改：\r\n"
        L"- KernelCpuMs/UserCpuMs/WorkingSet/PrivateUsage/IO计数/PageFaultCount：系统统计计数，只能由内核/调度器/内存管理器更新。\r\n"
        L"- VirtualAddressRegionPreview：地址空间枚举结果；应通过 VirtualAllocEx/VirtualProtectEx/Unmap/Map 等专门操作改变。\r\n"
        L"- RegionCount/CommitBytes/MappedBytes/ImageBytes/PrivateBytes：统计结果，不是单一字段。\r\n"
        L"- HeapCount/HeapBlock：需要堆管理器一致性，不在 PEB 页直接写。\r\n"
        L"- ProcessParameters 指针/Environment 指针：Light 当前仅开放亲和性和优先级写入，远程字符串及指针写入未启用。",
        true,
        true,
        8,
        542,
        -8,
        118);
    if (actionTask_ && actionTask_->running()) {
        setBackgroundActionControlsEnabled(false);
    }
    return true;
}

void ProcessDetailPage::populateEvidenceTab() {
    const ProcessR0AuditInfo* detail = findAuditScope(snapshot_.r0AuditRows, L"ProcessDetail");
    const ProcessR0AuditInfo* protection = findAuditSource(snapshot_.r0AuditRows, L"EP.Protection");
    const ProcessR0AuditInfo* signature = findAuditSource(snapshot_.r0AuditRows, L"EP.SignatureLevel");
    const ProcessR0AuditInfo* sectionSignature = findAuditSource(snapshot_.r0AuditRows, L"EP.SectionSignatureLevel");
    const ProcessR0AuditInfo* objectTable = findAuditSource(snapshot_.r0AuditRows, L"EP.ObjectTable");
    const ProcessR0AuditInfo* sectionObject = findAuditSource(snapshot_.r0AuditRows, L"EP.SectionObject");

    setControlText(
        TabIndex::kEvidence,
        kEvidenceR0Status,
        detail ? detail->anomalyText : (snapshot_.r0AuditSucceeded ? L"Partial" : L"Unavailable"));
    const std::wstring kCapability = detail ? extractDetailValue(detail->detailText, L"dyn") : std::wstring{};
    setControlText(TabIndex::kEvidence, kEvidenceCapability, kCapability.empty() ? L"Unavailable" : kCapability);
    setControlText(
        TabIndex::kEvidence,
        kEvidenceImagePath,
        snapshot_.basic.imagePath.empty() ? L"-" : snapshot_.basic.imagePath);

    const std::wstring kObjectAddress = detail ? extractDetailValue(detail->detailText, L"objectTable") : std::wstring{};
    const std::wstring kSectionAddress = detail ? extractDetailValue(detail->detailText, L"section") : std::wstring{};
    setControlText(
        TabIndex::kEvidence,
        kEvidenceHandleTable,
        kObjectAddress.empty() ? L"Unavailable" : L"HandleTable available: " + kObjectAddress + L" (R0 process detail)");
    setControlText(
        TabIndex::kEvidence,
        kEvidenceSectionObject,
        kSectionAddress.empty() ? L"Unavailable" : L"SectionObject available: " + kSectionAddress + L" (R0 process detail)");

    const auto kFieldValue = [](const ProcessR0AuditInfo* row) {
        const std::wstring kValue = row ? extractDetailValue(row->detailText, L"value") : std::wstring{};
        if (kValue.empty()) {
            return std::wstring(L"Unavailable");
        }
        std::uint64_t parsed = 0;
        return parseUnsigned(kValue, parsed) ? formatByteHex(parsed) : kValue;
    };
    const auto kFieldOffset = [](const ProcessR0AuditInfo* row) {
        const std::wstring kValue = row ? extractDetailValue(row->detailText, L"offset") : std::wstring{};
        return kValue.empty() ? std::wstring(L"Unavailable") : kValue;
    };
    const auto kFieldSource = [](const ProcessR0AuditInfo* row) {
        return row ? std::wstring(L"R0 runtime field sample") : std::wstring(L"Unavailable");
    };

    setControlText(TabIndex::kEvidence, kEvidenceProtection, kFieldValue(protection));
    setControlText(TabIndex::kEvidence, kEvidenceSignature, kFieldValue(signature));
    setControlText(TabIndex::kEvidence, kEvidenceSectionSignature, kFieldValue(sectionSignature));
    setControlText(TabIndex::kEvidence, kEvidenceSessionSource, snapshot_.basicSucceeded ? L"Win32 snapshot" : L"Unavailable");
    setControlText(TabIndex::kEvidence, kEvidenceImagePathSource, snapshot_.basic.imagePath.empty() ? L"Unavailable" : L"Win32 snapshot");
    setControlText(TabIndex::kEvidence, kEvidenceProtectionSource, kFieldSource(protection));
    setControlText(TabIndex::kEvidence, kEvidenceSignatureSource, kFieldSource(signature));
    setControlText(TabIndex::kEvidence, kEvidenceSectionSignatureSource, kFieldSource(sectionSignature));
    setControlText(TabIndex::kEvidence, kEvidenceObjectTableSource, detail || objectTable ? L"R0 process detail" : L"Unavailable");
    setControlText(TabIndex::kEvidence, kEvidenceSectionObjectSource, detail || sectionObject ? L"R0 process detail" : L"Unavailable");
    setControlText(TabIndex::kEvidence, kEvidenceProtectionOffset, kFieldOffset(protection));
    setControlText(TabIndex::kEvidence, kEvidenceSignatureOffset, kFieldOffset(signature));
    setControlText(TabIndex::kEvidence, kEvidenceSectionSignatureOffset, kFieldOffset(sectionSignature));
    setControlText(TabIndex::kEvidence, kEvidenceObjectTableOffset, kFieldOffset(objectTable));
    setControlText(TabIndex::kEvidence, kEvidenceSectionObjectOffset, kFieldOffset(sectionObject));
}

void ProcessDetailPage::populatePebTab() {
    if (!pebLoaded_) {
        setPageStatus(TabIndex::kPeb, kPebStatus, L"● 尚未刷新");
        setControlText(TabIndex::kPeb, kPebOutput, L"PEB 与地址空间摘要将在此处显示。");
    }
}

bool ProcessDetailPage::handleEvidenceCommand(const int controlId) {
    if (controlId == kEvidenceRefreshSection) {
        refreshSectionReport();
        return true;
    }
    return false;
}

bool ProcessDetailPage::handlePebCommand(const int controlId) {
    if (controlId == kPebRefresh) {
        refreshPebReport();
        return true;
    }
    if (controlId == kPebApply) {
        applyPebEdits();
        return true;
    }
    return false;
}

void ProcessDetailPage::refreshSectionReport() {
    if (!evidenceTask_) {
        setPageStatus(TabIndex::kEvidence, kEvidenceSectionStatus, L"● R0 证据后台任务不可用。");
        return;
    }
    setPageStatus(TabIndex::kEvidence, kEvidenceSectionStatus, L"● 正在查询 Section/ControlArea...");
    const DWORD kProcessId = processId_;
    const ULONGLONG kExpectedCreationTime100ns = expectedCreationTime100ns_;
    evidenceTask_->request(
        [kProcessId, kExpectedCreationTime100ns] {
            ProcessDetailCollector collector;
            return collector.collect(kProcessId, kExpectedCreationTime100ns);
        },
        [this](std::uint64_t, std::optional<ProcessDetailSnapshot>&& result, std::exception_ptr error) {
            if (error || !result.has_value()) {
                setPageStatus(TabIndex::kEvidence, kEvidenceSectionStatus, L"● R0 证据后台查询异常结束。");
                return;
            }
            snapshot_.r0AuditRows = std::move(result->r0AuditRows);
            snapshot_.r0AuditSucceeded = result->r0AuditSucceeded;
            if (!result->basic.imagePath.empty()) {
                snapshot_.basic.imagePath = std::move(result->basic.imagePath);
            }
            populateEvidenceTab();
            renderSectionReport();
        });
}

void ProcessDetailPage::renderSectionReport() {
    std::wostringstream report;
    report << L"[R0 Process Runtime Detail]\r\n";
    report << L"PID: " << processId_ << L"\r\n";
    report << L"R0 Audit: " << (snapshot_.r0AuditSucceeded ? L"OK" : L"Unavailable/Partial") << L"\r\n";
    report << L"Rows: " << snapshot_.r0AuditRows.size() << L"\r\n\r\n";
    report << L"[Process Detail Evidence]\r\n";
    for (std::size_t index = 0; index < snapshot_.r0AuditRows.size(); ++index) {
        const ProcessR0AuditInfo& row = snapshot_.r0AuditRows[index];
        report << L"#" << index + 1U << L" " << row.scope;
        if (row.threadId != 0) { report << L" TID=" << row.threadId; }
        report << L"\r\n";
        report << L"  Object=" << formatHex(row.objectAddress)
               << L" Related=" << formatHex(row.relatedObjectAddress)
               << L" Start=" << formatHex(row.startAddress) << L"\r\n";
        report << L"  Source=" << (row.sourceText.empty() ? L"Unavailable" : row.sourceText)
               << L" Status=" << (row.anomalyText.empty() ? L"Unavailable" : row.anomalyText)
               << L" Confidence=" << row.confidence << L"\r\n";
        if (!row.detailText.empty()) {
            report << L"  Detail=" << row.detailText << L"\r\n";
        }
    }
    report << L"\r\n[R0 Section Query]\r\n";
    const ProcessR0AuditInfo* detail = findAuditScope(snapshot_.r0AuditRows, L"ProcessDetail");
    if (detail) {
        report << L"ProcessObject: " << formatHex(detail->objectAddress) << L"\r\n";
        report << L"ObjectTable: " << extractDetailValue(detail->detailText, L"objectTable") << L"\r\n";
        report << L"SectionObject: " << extractDetailValue(detail->detailText, L"section") << L"\r\n";
        report << L"DynDataCapability: " << extractDetailValue(detail->detailText, L"dyn") << L"\r\n";
        report << L"Status: " << detail->anomalyText << L"\r\n";
    } else {
        report << L"<empty or unavailable>\r\n";
    }
    report << L"[Mappings]\r\n";
    report << L"  当前 Light 快照未携带独立映射数组；上方审计行保留驱动返回的完整只读证据。\r\n";

    setControlText(TabIndex::kEvidence, kEvidenceSectionOutput, report.str());
    setPageStatus(
        TabIndex::kEvidence,
        kEvidenceSectionStatus,
        std::wstring(L"● 后台刷新完成") +
            (snapshot_.r0AuditSucceeded ? L"" : L" | R0证据部分不可用"));
    sectionLoaded_ = true;
}

void ProcessDetailPage::refreshPebReport() {
    if (!pebTask_) {
        setPageStatus(TabIndex::kPeb, kPebStatus, L"● PEB 后台任务不可用。");
        return;
    }
    setPageStatus(TabIndex::kPeb, kPebStatus, L"● 正在刷新PEB...");
    const int kSelectedTarget = static_cast<int>(
        ::SendMessageW(findControl(TabIndex::kPeb, kPebTarget), CB_GETCURSEL, 0, 0));
    const DWORD kProcessId = processId_;
    const ULONGLONG kExpectedProcessCreationTime100ns = expectedCreationTime100ns_;
    pebTask_->request(
        [kProcessId, kExpectedProcessCreationTime100ns, kSelectedTarget] {
            return collectPebSnapshot(kProcessId, kExpectedProcessCreationTime100ns, kSelectedTarget);
        },
        [this](std::uint64_t, std::optional<ProcessPebSnapshot>&& result, std::exception_ptr error) {
            if (error || !result.has_value()) {
                setPageStatus(TabIndex::kPeb, kPebStatus, L"● PEB 后台查询异常结束。");
                return;
            }
            setControlText(TabIndex::kPeb, kPebOutput, result->reportText);
            if (!result->identityMatched) {
                setControlText(TabIndex::kPeb, kPebAffinity, L"Unavailable");
                ::SendMessageW(findControl(TabIndex::kPeb, kPebPriority), CB_SETCURSEL, static_cast<WPARAM>(-1), 0);
                setControlText(TabIndex::kPeb, kPebCommandLine, L"Unavailable");
                setControlText(TabIndex::kPeb, kPebImagePath, L"Unavailable");
                setControlText(TabIndex::kPeb, kPebCurrentDirectory, L"Unavailable");
                setControlText(TabIndex::kPeb, kPebEnvironmentName, L"Unavailable");
                setControlText(TabIndex::kPeb, kPebImageBase, L"Unavailable");
            } else {
                if (result->affinityKnown) {
                    setControlText(TabIndex::kPeb, kPebAffinity, result->affinityText);
                }
                if (result->priorityKnown) {
                    ::SendMessageW(
                        findControl(TabIndex::kPeb, kPebPriority),
                        CB_SETCURSEL,
                        static_cast<WPARAM>(result->priorityComboIndex),
                        0);
                }
                if (result->selectedPebKnown) {
                    setControlText(TabIndex::kPeb, kPebCommandLine, result->commandLine);
                    setControlText(TabIndex::kPeb, kPebImagePath, result->imagePath);
                    setControlText(TabIndex::kPeb, kPebCurrentDirectory, result->currentDirectory);
                    setControlText(TabIndex::kPeb, kPebImageBase, result->imageBase);
                }
            }
            setPageStatus(TabIndex::kPeb, kPebStatus, result->statusText);
            pebLoaded_ = result->completed && result->identityMatched;
        });

}

void ProcessDetailPage::applyPebEdits() {
    const int kConfirmation = ::MessageBoxW(
        hwnd_,
        L"即将修改目标进程的亲和性或优先级。\r\n\r\n"
        L"Light 当前不写入远程 PEB 字符串、环境块或 ImageBaseAddress；这些字段会逐项报告为“未启用”，不会伪装成功。\r\n"
        L"是否继续？",
        L"确认修改进程属性",
        MB_ICONWARNING | MB_YESNO | MB_DEFBUTTON2);
    if (kConfirmation != IDYES) {
        return;
    }

    const std::wstring kCommandLine = controlText(TabIndex::kPeb, kPebCommandLine);
    const std::wstring kImagePath = controlText(TabIndex::kPeb, kPebImagePath);
    const std::wstring kCurrentDirectory = controlText(TabIndex::kPeb, kPebCurrentDirectory);
    const std::wstring kEnvironmentName = controlText(TabIndex::kPeb, kPebEnvironmentName);
    const std::wstring kImageBase = controlText(TabIndex::kPeb, kPebImageBase);
    const std::wstring kAffinityText = trimCopy(controlText(TabIndex::kPeb, kPebAffinity));
    const int kPriorityIndex = static_cast<int>(
        ::SendMessageW(findControl(TabIndex::kPeb, kPebPriority), CB_GETCURSEL, 0, 0));
    const DWORD kProcessId = processId_;
    const ULONGLONG kExpectedProcessCreationTime100ns = expectedCreationTime100ns_;
    executeBackgroundAction(
        TabIndex::kPeb,
        kPebStatus,
        L"● 正在后台修改进程属性…",
        [kProcessId, kExpectedProcessCreationTime100ns, kCommandLine, kImagePath, kCurrentDirectory, kEnvironmentName, kImageBase, kAffinityText, kPriorityIndex] {
            ProcessDetailActionResult action{};
            ksword::core::UniqueHandle verifiedProcess;
            std::wstring identityError;
            if (!ProcessDetailPage::openVerifiedProcessActionTarget(
                    kProcessId,
                    kExpectedProcessCreationTime100ns,
                    PROCESS_QUERY_INFORMATION | PROCESS_SET_INFORMATION,
                    verifiedProcess,
                    identityError)) {
                action.statusText = L"● PEB 修改失败：" + identityError;
                action.dialogTitle = L"PEB 修改失败";
                action.dialogText = identityError;
                action.dialogIcon = MB_ICONERROR;
                return action;
            }
            HANDLE process = verifiedProcess.get();

            std::vector<std::wstring> results;
            int successCount = 0;
            int failCount = 0;
            int skippedCount = 0;
            const auto kSkippedRemote = [&](const wchar_t* field, const std::wstring& value) {
                if (value.empty()) { return; }
                ++skippedCount;
                results.push_back(std::wstring(L"[跳过] ") + field + L"：Light 远程PEB写入未启用，未执行任何写操作。");
            };
            kSkippedRemote(L"CommandLine", kCommandLine);
            kSkippedRemote(L"ImagePathName", kImagePath);
            kSkippedRemote(L"CurrentDirectory", kCurrentDirectory);
            if (!trimCopy(kEnvironmentName).empty()) {
                kSkippedRemote(L"Environment", kEnvironmentName);
            }
            kSkippedRemote(L"ImageBaseAddress", kImageBase);

            if (kAffinityText.empty()) {
                ++skippedCount;
                results.push_back(L"[跳过] AffinityMask：输入为空。");
            } else {
                std::uint64_t requestedAffinity = 0;
                ULONG_PTR currentAffinity = 0;
                ULONG_PTR systemAffinity = 0;
                if (!parseUnsigned(kAffinityText, requestedAffinity) || requestedAffinity == 0 ||
                    requestedAffinity > std::numeric_limits<ULONG_PTR>::max()) {
                    ++failCount;
                    results.push_back(L"[失败] AffinityMask：格式无效、为0或超过当前位宽。");
                } else if (::GetProcessAffinityMask(process, &currentAffinity, &systemAffinity) &&
                           requestedAffinity == static_cast<std::uint64_t>(currentAffinity)) {
                    ++skippedCount;
                    results.push_back(L"[跳过] AffinityMask：未变化。");
                } else if (::SetProcessAffinityMask(process, static_cast<ULONG_PTR>(requestedAffinity))) {
                    ++successCount;
                    results.push_back(L"[成功] AffinityMask：已设置为 " + formatHex(requestedAffinity) + L"。");
                } else {
                    ++failCount;
                    results.push_back(L"[失败] AffinityMask：SetProcessAffinityMask失败(" +
                        std::to_wstring(::GetLastError()) + L")。");
                }
            }

            const DWORD kRequestedPriority = priorityClassByComboIndex(kPriorityIndex);
            if (kRequestedPriority == 0) {
                ++skippedCount;
                results.push_back(L"[跳过] PriorityClass：选择为不修改。");
            } else {
                const DWORD kCurrentPriority = ::GetPriorityClass(process);
                if (kCurrentPriority == kRequestedPriority) {
                    ++skippedCount;
                    results.push_back(L"[跳过] PriorityClass：未变化。");
                } else if (::SetPriorityClass(process, kRequestedPriority)) {
                    ++successCount;
                    results.push_back(L"[成功] PriorityClass：已设置为 " + priorityClassText(kRequestedPriority) + L"。");
                } else {
                    ++failCount;
                    results.push_back(L"[失败] PriorityClass：SetPriorityClass失败(" +
                        std::to_wstring(::GetLastError()) + L")。");
                }
            }
            std::wostringstream resultText;
            resultText << L"成功 " << successCount << L"，失败 " << failCount << L"，跳过 " << skippedCount << L"\r\n\r\n";
            for (const std::wstring& line : results) {
                resultText << line << L"\r\n";
            }
            action.statusText =
                L"● PEB修改完成：成功 " + std::to_wstring(successCount) +
                L"，失败 " + std::to_wstring(failCount) +
                L"，跳过 " + std::to_wstring(skippedCount);
            action.dialogTitle = L"PEB 修改结果";
            action.dialogText = resultText.str();
            action.dialogIcon = MB_ICONINFORMATION;
            action.refreshPebReport = true;
            return action;
        });

}

} // namespace Ksword::Features::process_detail

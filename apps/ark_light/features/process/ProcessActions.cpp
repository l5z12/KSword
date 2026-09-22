#include "ProcessActions.h"

#include "../../../../shared/ark_client/ArkDriverClient.h"
#include "../../../../shared/platform/process/Process.h"
#include "../../core/Common.h"

#include <algorithm>
#include <cstring>
#include <cstdint>
#include <fstream>
#include <functional>
#include <iomanip>
#include <shellapi.h>
#include <sstream>
#include <string>
#include <tlhelp32.h>
#include <utility>
#include <unordered_map>
#include <unordered_set>

#ifndef SECURITY_MANDATORY_MEDIUM_PLUS_RID
#define SECURITY_MANDATORY_MEDIUM_PLUS_RID (0x00002100L)
#endif

namespace ksword::features::process {
namespace {
constexpr ULONG kProcessBreakOnTerminationInfoClass = 29UL;
constexpr ULONG kProcessPowerThrottlingInfoClass = 4UL;
constexpr ULONG kProcessPowerThrottlingCurrentVersion = 1UL;
constexpr ULONG kProcessPowerThrottlingExecutionSpeed = 0x1UL;
constexpr DWORD kProcessSuspendResumeAccess = 0x0800UL;

using NtSuspendProcessFn = LONG(NTAPI*)(HANDLE);
using NtResumeProcessFn = LONG(NTAPI*)(HANDLE);
using NtSetInformationProcessFn = LONG(NTAPI*)(HANDLE, ULONG, PVOID, ULONG);
using SetProcessInformationFn = BOOL(WINAPI*)(HANDLE, ULONG, LPVOID, DWORD);

// ProcessPowerThrottlingStateNative mirrors PROCESS_POWER_THROTTLING_STATE
// without requiring a new SDK. Inputs are written by setEfficiencyModeForPid;
// processing passes the structure to SetProcessInformation; it returns no value.
struct ProcessPowerThrottlingStateNative {
    ULONG version = 0;
    ULONG controlMask = 0;
    ULONG stateMask = 0;
};

// utf8ToWide converts ArkDriverClient diagnostic messages into the Win32 UI
// encoding. Input is a UTF-8/narrow diagnostic string; processing asks Windows
// for the exact UTF-16 size and falls back to byte widening when conversion is
// impossible; output is safe for status text and message boxes.
std::wstring utf8ToWide(const std::string& text) {
    if (text.empty()) {
        return {};
    }

    const int kRequired = ::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.c_str(), static_cast<int>(text.size()), nullptr, 0);
    if (kRequired > 0) {
        std::wstring wide(static_cast<std::size_t>(kRequired), L'\0');
        ::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.c_str(), static_cast<int>(text.size()), wide.data(), kRequired);
        return wide;
    }

    std::wstring fallback;
    fallback.reserve(text.size());
    for (const unsigned char kCh : text) {
        fallback.push_back(static_cast<wchar_t>(kCh));
    }
    return fallback;
}

std::wstring pidListText(const std::vector<DWORD>& pids) {
    std::wstring text;
    for (std::size_t i = 0; i < pids.size(); ++i) {
        if (i != 0) {
            text += L", ";
        }
        text += std::to_wstring(pids[i]);
    }
    return text.empty() ? L"<none>" : text;
}

// writeClipboardText copies Unicode operation handoff text to the clipboard.
// Input is owner HWND (optional) and text; processing transfers GMEM_MOVEABLE
// memory to the OS clipboard; output reports whether the copy succeeded.
bool writeClipboardText(HWND owner, const std::wstring& text) {
    if (!::OpenClipboard(owner)) {
        return false;
    }
    ::EmptyClipboard();
    const SIZE_T kBytes = (text.size() + 1) * sizeof(wchar_t);
    HGLOBAL memory = ::GlobalAlloc(GMEM_MOVEABLE, kBytes);
    if (!memory) {
        ::CloseClipboard();
        return false;
    }
    void* target = ::GlobalLock(memory);
    if (!target) {
        ::GlobalFree(memory);
        ::CloseClipboard();
        return false;
    }
    std::memcpy(target, text.c_str(), kBytes);
    ::GlobalUnlock(memory);
    const bool kOk = ::SetClipboardData(CF_UNICODETEXT, memory) != nullptr;
    if (!kOk) {
        ::GlobalFree(memory);
    }
    ::CloseClipboard();
    return kOk;
}

const ProcessSnapshotRow* findRowByPid(const std::vector<ProcessSnapshotRow>& rows, DWORD pid) {
    const auto kIt = std::find_if(rows.begin(), rows.end(), [pid](const ProcessSnapshotRow& row) {
        return row.processId == pid;
    });
    return kIt == rows.end() ? nullptr : &*kIt;
}

// buildProcessActionTargets preserves the exact process instances selected by
// the user. Missing rows remain explicit zero-identity targets so mutations fail
// closed instead of falling back to whatever later owns the same PID.
std::vector<ProcessSnapshotRow> buildProcessActionTargets(
    const std::vector<DWORD>& selectedPids,
    const std::vector<ProcessSnapshotRow>& snapshotRows) {
    std::vector<ProcessSnapshotRow> targets;
    targets.reserve(selectedPids.size());
    std::unordered_set<DWORD> visitedPids;
    visitedPids.reserve(selectedPids.size());
    for (const DWORD kPid : selectedPids) {
        if (kPid == 0U || !visitedPids.insert(kPid).second) {
            continue;
        }
        const ProcessSnapshotRow* row = findRowByPid(snapshotRows, kPid);
        if (row != nullptr) {
            targets.push_back(*row);
            continue;
        }
        ProcessSnapshotRow missingTarget{};
        missingTarget.processId = kPid;
        targets.push_back(std::move(missingTarget));
    }
    return targets;
}

// collectR3ProcessTreePids expands the selected R3 processes into descendant-
// first termination targets. R0-only audit rows are deliberately excluded from
// both roots and descendants, so driver evidence never changes tree discovery.
std::vector<DWORD> collectR3ProcessTreePids(
    const std::vector<DWORD>& selectedPids,
    const std::vector<ProcessSnapshotRow>& snapshotRows) {
    std::unordered_map<DWORD, std::vector<DWORD>> childrenByParentPid;
    std::unordered_set<DWORD> r3PidSet;
    childrenByParentPid.reserve(snapshotRows.size());
    r3PidSet.reserve(snapshotRows.size());

    for (const ProcessSnapshotRow& row : snapshotRows) {
        if (row.r0KernelOnly || row.processId == 0U || !r3PidSet.insert(row.processId).second) {
            continue;
        }
        childrenByParentPid[row.parentProcessId].push_back(row.processId);
    }

    for (auto& childPair : childrenByParentPid) {
        std::vector<DWORD>& childPids = childPair.second;
        std::sort(childPids.begin(), childPids.end());
    }

    std::vector<DWORD> treePids;
    treePids.reserve(r3PidSet.size());
    std::unordered_set<DWORD> visitedPids;
    visitedPids.reserve(r3PidSet.size());
    std::function<void(DWORD)> appendSubtree;
    appendSubtree =
        [&childrenByParentPid, &treePids, &visitedPids, &appendSubtree](const DWORD processId) {
        if (!visitedPids.insert(processId).second) {
            return;
        }

        const auto kChildIt = childrenByParentPid.find(processId);
        if (kChildIt != childrenByParentPid.end()) {
            for (const DWORD kChildPid : kChildIt->second) {
                appendSubtree(kChildPid);
            }
        }
        treePids.push_back(processId);
    };

    for (const DWORD kSelectedPid : selectedPids) {
        if (r3PidSet.find(kSelectedPid) != r3PidSet.end()) {
            appendSubtree(kSelectedPid);
        }
    }
    return treePids;
}

ProcessActionResult failureResult(const wchar_t* title, const std::vector<DWORD>& pids, const wchar_t* reason) {
    ProcessActionResult result;
    result.success = false;
    result.title = title;
    result.detail = std::wstring(reason) + L"\r\nTarget PID(s): " + pidListText(pids);
    return result;
}

// win32ErrorText formats the current or supplied Win32 error. Input is the error
// code; processing delegates message formatting to Core; output is display text.
std::wstring win32ErrorText(const DWORD error) {
    return L"Win32 " + std::to_wstring(error) + L": " + ksword::core::lastErrorMessage(error);
}

// Hex32 formats NTSTATUS-style signed LONG values without losing the raw bits.
// Input is an NTSTATUS-compatible value; output is uppercase 8-digit hex text.
std::wstring hex32(const LONG status) {
    std::wostringstream stream;
    stream << L"0x" << std::uppercase << std::hex << std::setw(8) << std::setfill(L'0')
           << static_cast<std::uint32_t>(status);
    return stream.str();
}

// Hex64 formats pointer-sized diagnostics without truncating kernel/user
// addresses. Input is a 64-bit value from ArkDriverClient; output is a stable
// uppercase hexadecimal string used only for display.
std::wstring hex64(const std::uint64_t value) {
    std::wostringstream stream;
    stream << L"0x" << std::uppercase << std::hex << value;
    return stream.str();
}

// asciiLiteralToWide widens short export names or fixed ASCII diagnostics.
// Input is a null-terminated ASCII string; processing widens byte-for-byte;
// output is empty when input is null.
std::wstring asciiLiteralToWide(const char* text) {
    if (!text) {
        return {};
    }
    std::wstring wide;
    while (*text) {
        wide.push_back(static_cast<wchar_t>(*text));
        ++text;
    }
    return wide;
}

// NtProc resolves one ntdll export by name. Input is an ANSI export name;
// processing uses the already-loaded ntdll module or loads it; output is null
// when the export cannot be found.
FARPROC ntProc(const char* name) {
    if (!name || name[0] == '\0') {
        return nullptr;
    }
    HMODULE ntdll = ::GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) {
        ntdll = ::LoadLibraryW(L"ntdll.dll");
    }
    return ntdll ? ::GetProcAddress(ntdll, name) : nullptr;
}

// enableCurrentProcessPrivilege enables one privilege on the current token.
// Input is a privilege name such as SE_DEBUG_NAME; processing adjusts the
// process token; output reports whether Windows accepted and assigned it.
bool enableCurrentProcessPrivilege(const wchar_t* privilegeName, std::wstring& detail) {
    HANDLE rawToken = nullptr;
    if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &rawToken)) {
        detail = L"OpenProcessToken failed: " + win32ErrorText(::GetLastError());
        return false;
    }
    ksword::core::UniqueHandle token(rawToken);

    LUID luid{};
    if (!::LookupPrivilegeValueW(nullptr, privilegeName, &luid)) {
        detail = L"LookupPrivilegeValueW failed: " + win32ErrorText(::GetLastError());
        return false;
    }

    TOKEN_PRIVILEGES privileges{};
    privileges.PrivilegeCount = 1;
    privileges.Privileges[0].Luid = luid;
    privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!::AdjustTokenPrivileges(token.get(), FALSE, &privileges, sizeof(privileges), nullptr, nullptr)) {
        detail = L"AdjustTokenPrivileges failed: " + win32ErrorText(::GetLastError());
        return false;
    }

    const DWORD kAdjustError = ::GetLastError();
    if (kAdjustError != ERROR_SUCCESS) {
        detail = L"AdjustTokenPrivileges did not assign privilege: " + win32ErrorText(kAdjustError);
        return false;
    }
    detail = std::wstring(privilegeName ? privilegeName : L"<null>") + L" enabled";
    return true;
}

// appendIoLine records one per-PID operation result. Inputs are a mutable
// details buffer, PID, operation label, success bit and driver/Win32 message;
// processing emits compact multiline diagnostics; no value is returned.
void appendIoLine(std::wstring& detail, DWORD pid, const wchar_t* operation, bool ok, const std::wstring& message) {
    detail += L"PID " + std::to_wstring(pid) + L" ";
    detail += operation;
    detail += ok ? L": OK" : L": FAIL";
    if (!message.empty()) {
        detail += L" | ";
        detail += message;
    }
    detail += L"\r\n";
}

// appendIoLine records a global non-PID operation such as clearing hidden marks.
// Inputs mirror the PID overload except there is no target process id.
void appendIoLine(std::wstring& detail, const wchar_t* operation, bool ok, const std::wstring& message) {
    detail += operation;
    detail += ok ? L": OK" : L": FAIL";
    if (!message.empty()) {
        detail += L" | ";
        detail += message;
    }
    detail += L"\r\n";
}

// isProtectedSystemPid blocks obviously invalid targets before sending mutating
// process IOCTLs. Input is a PID; output is true for PID 0..4, matching the
// original KswordARK R0 helpers.
bool isProtectedSystemPid(DWORD pid) {
    return pid == 0 || pid <= 4;
}

// isProcessPresentBySnapshot checks target liveness with the same Toolhelp
// snapshot semantics as the full ProcessDock aggregate termination action.
// A failed snapshot is conservatively treated as "still present" so a
// transient query failure cannot report a process as terminated.
bool isProcessPresentBySnapshot(DWORD pid, bool* queryOkOut) {
    if (queryOkOut) {
        *queryOkOut = false;
    }

    HANDLE snapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return true;
    }

    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (!::Process32FirstW(snapshot, &entry)) {
        ::CloseHandle(snapshot);
        return true;
    }

    bool present = false;
    do {
        if (entry.th32ProcessID == pid) {
            present = true;
            break;
        }
    } while (::Process32NextW(snapshot, &entry));

    ::CloseHandle(snapshot);
    if (queryOkOut) {
        *queryOkOut = true;
    }
    return present;
}

// openProcessForAction retains a verified process handle for the duration of a
// mutation, so a PID cannot be silently rebound to a different snapshot row.
ksword::core::UniqueHandle openProcessForAction(
    DWORD pid,
    ULONGLONG expectedCreationTime100ns,
    DWORD access,
    std::wstring& errorText,
    bool rejectProtected = true);
// executeMultiMethodTerminate mirrors the full ProcessDock right-click action:
// each target is checked after every method and the chain stops immediately
// once its exit has been confirmed. The two-round cap prevents an unresponsive
// target from leaving the Light UI in an unbounded operation.
ProcessActionResult executeMultiMethodTerminate(const std::vector<ProcessSnapshotRow>& actionTargets) {
    ProcessActionResult result;
    result.title = L"结束进程(组合方法链)";
    result.success = true;

    struct TerminateMethodEntry {
        const wchar_t* methodName = nullptr;
        std::function<bool(std::uint32_t, std::string*)> invoke;
    };

    const std::vector<TerminateMethodEntry> kMethods{
        { L"TerminateProcess(Kernel32)", [](std::uint32_t pid, std::string* detail) { return ks::process::terminateProcessByWin32(pid, detail); } },
        { L"NtTerminateProcess/ZwTerminateProcess", [](std::uint32_t pid, std::string* detail) { return ks::process::terminateProcessByNtNative(pid, detail); } },
        { L"WTSTerminateProcess(WTS API)", [](std::uint32_t pid, std::string* detail) { return ks::process::terminateProcessByWtsApi(pid, detail); } },
        { L"WinStationTerminateProcess(winsta)", [](std::uint32_t pid, std::string* detail) { return ks::process::terminateProcessByWinStationApi(pid, detail); } },
        { L"TerminateJobObject(Job)", [](std::uint32_t pid, std::string* detail) { return ks::process::terminateProcessByJobObject(pid, detail); } },
        { L"NtTerminateJobObject/ZwTerminateJobObject", [](std::uint32_t pid, std::string* detail) { return ks::process::terminateProcessByNtJobObject(pid, detail); } },
        { L"RmShutdown(Restart Manager)", [](std::uint32_t pid, std::string* detail) { return ks::process::terminateProcessByRestartManager(pid, false, detail); } },
        { L"RmShutdown(Restart Manager, force)", [](std::uint32_t pid, std::string* detail) { return ks::process::terminateProcessByRestartManager(pid, true, detail); } },
        { L"DuplicateHandle(-1)+TerminateProcess", [](std::uint32_t pid, std::string* detail) { return ks::process::terminateProcessByDuplicateHandlePseudo(pid, detail); } },
        { L"TerminateThread(全部线程)", [](std::uint32_t pid, std::string* detail) { return ks::process::terminateAllThreadsByPid(pid, detail); } },
        { L"NtTerminateThread/ZwTerminateThread(全部线程)", [](std::uint32_t pid, std::string* detail) { return ks::process::terminateAllThreadsByPidNtNative(pid, detail); } },
        { L"DebugActiveProcess 调试附加", [](std::uint32_t pid, std::string* detail) { return ks::process::terminateProcessByDebugAttach(pid, detail); } },
        { L"ntsd -c q -p <pid>", [](std::uint32_t pid, std::string* detail) { return ks::process::terminateProcessByNtsdCommand(pid, detail); } },
        { L"NtUnmapViewOfSection 卸载 ntdll.dll", [](std::uint32_t pid, std::string* detail) { return ks::process::terminateProcessByNtUnmapNtdll(pid, detail); } }
    };

    for (const ProcessSnapshotRow& target : actionTargets) {
        const DWORD kPid = target.processId;
        if (isProtectedSystemPid(kPid)) {
            appendIoLine(result.detail, kPid, L"组合结束", false, L"protected system PID");
            result.success = false;
            continue;
        }

        std::wstring identityError;
        ksword::core::UniqueHandle verifiedProcess = openProcessForAction(
            kPid,
            target.creationTime100ns,
            PROCESS_QUERY_LIMITED_INFORMATION,
            identityError);
        if (!verifiedProcess.valid()) {
            appendIoLine(result.detail, kPid, L"组合结束", false, identityError);
            result.success = false;
            continue;
        }
        // verifiedProcess stays open through all PID-only fallback methods.

        bool queryOk = false;
        if (!isProcessPresentBySnapshot(kPid, &queryOk)) {
            appendIoLine(result.detail, kPid, L"组合结束", true, L"目标进程已不存在，无需执行结束动作。");
            continue;
        }

        std::wostringstream detail;
        detail << L"PID " << kPid;
        if (!queryOk) {
            detail << L" | 初始存在性检查失败，继续执行方法链";
        }

        bool processExited = false;
        constexpr int kTerminateRoundLimit = 2;
        for (int round = 1; round <= kTerminateRoundLimit && !processExited; ++round) {
            for (const TerminateMethodEntry& method : kMethods) {
                std::string methodDetail;
                const bool kInvokeOk = method.invoke(kPid, &methodDetail);
                bool postQueryOk = false;
                const bool kStillPresent = isProcessPresentBySnapshot(kPid, &postQueryOk);
                detail << L"\r\n  Round " << round << L" | " << method.methodName
                       << L" | " << (kInvokeOk ? L"调用成功" : L"调用失败")
                       << L" | " << utf8ToWide(methodDetail.empty() ? "无附加信息" : methodDetail.c_str());
                if (postQueryOk) {
                    detail << (kStillPresent ? L" | 进程仍在运行" : L" | 已确认退出");
                } else {
                    detail << L" | 存在性检查失败，按仍在运行处理";
                }
                if (!kStillPresent) {
                    processExited = true;
                    break;
                }
            }
        }

        detail << (processExited ? L"\r\n  结果：已确认退出。" : L"\r\n  结果：两轮方法链后进程仍在运行。");
        result.detail += detail.str();
        result.detail += L"\r\n";
        result.success = result.success && processExited;
    }
    return result;
}

// openProcessForAction opens and identity-checks one local process action handle.
// Inputs are PID, expected snapshot creation time, and desired access; processing
// keeps the matching handle alive for the caller so PID-only fallback APIs cannot
// target a later process instance. Output is an owning handle or a diagnostic.
ksword::core::UniqueHandle openProcessForAction(
    const DWORD pid,
    const ULONGLONG expectedCreationTime100ns,
    const DWORD access,
    std::wstring& errorText,
    const bool rejectProtected) {
    if (rejectProtected && isProtectedSystemPid(pid)) {
        errorText = L"protected system PID";
        return ksword::core::UniqueHandle();
    }
    if (expectedCreationTime100ns == 0U) {
        errorText = L"process identity is unavailable; action skipped";
        return ksword::core::UniqueHandle();
    }

    const DWORD kRequestedAccess = access | PROCESS_QUERY_LIMITED_INFORMATION;
    HANDLE process = ::OpenProcess(kRequestedAccess, FALSE, pid);
    if (!process) {
        errorText = L"OpenProcess failed: " + win32ErrorText(::GetLastError());
        return ksword::core::UniqueHandle();
    }

    FILETIME creationTime{};
    FILETIME exitTime{};
    FILETIME kernelTime{};
    FILETIME userTime{};
    if (!::GetProcessTimes(process, &creationTime, &exitTime, &kernelTime, &userTime)) {
        errorText = L"GetProcessTimes failed: " + win32ErrorText(::GetLastError());
        ::CloseHandle(process);
        return ksword::core::UniqueHandle();
    }
    const ULONGLONG kActualCreationTime100ns =
        (static_cast<ULONGLONG>(creationTime.dwHighDateTime) << 32U) |
        static_cast<ULONGLONG>(creationTime.dwLowDateTime);
    if (kActualCreationTime100ns == 0U || kActualCreationTime100ns != expectedCreationTime100ns) {
        errorText = L"process identity changed (PID was reused); action skipped";
        ::CloseHandle(process);
        return ksword::core::UniqueHandle();
    }
    return ksword::core::UniqueHandle(process);
}

// holdProcessIdentityForDriverAction keeps a verified process object alive
// while a driver operation still addresses that object by PID.
bool holdProcessIdentityForDriverAction(
    const ProcessSnapshotRow& target,
    const wchar_t* operation,
    const bool rejectProtected,
    ProcessActionResult& result,
    ksword::core::UniqueHandle& identityHold) {
    std::wstring identityError;
    identityHold = openProcessForAction(
        target.processId,
        target.creationTime100ns,
        PROCESS_QUERY_LIMITED_INFORMATION,
        identityError,
        rejectProtected);
    if (identityHold.valid()) {
        return true;
    }
    appendIoLine(result.detail, target.processId, operation, false, identityError);
    result.success = false;
    return false;
}

// ntSuspendOrResumeProcess invokes NtSuspendProcess or NtResumeProcess for one
// PID. Inputs are PID and desired direction; processing uses ntdll dynamically;
// output is true on NT_SUCCESS and a diagnostic otherwise.
bool ntSuspendOrResumeProcess(DWORD pid, ULONGLONG expectedCreationTime100ns, bool resume, std::wstring& message) {
    const char* exportName = resume ? "NtResumeProcess" : "NtSuspendProcess";
    const FARPROC kProc = ntProc(exportName);
    if (!kProc) {
        message = asciiLiteralToWide(exportName) + L" not available";
        return false;
    }

    std::wstring openError;
    ksword::core::UniqueHandle process = openProcessForAction(pid, expectedCreationTime100ns, kProcessSuspendResumeAccess, openError);
    if (!process.valid()) {
        message = openError;
        return false;
    }

    const LONG kStatus = resume
        ? reinterpret_cast<NtResumeProcessFn>(kProc)(process.get())
        : reinterpret_cast<NtSuspendProcessFn>(kProc)(process.get());
    if (kStatus >= 0) {
        message = hex32(kStatus);
        return true;
    }
    message = asciiLiteralToWide(exportName) + L" failed: " + hex32(kStatus);
    return false;
}

// setCriticalFlagForPid sets ProcessBreakOnTermination for one process. Inputs
// are PID and target state; processing enables SeDebugPrivilege best-effort then
// calls NtSetInformationProcess; output reports operation success.
bool setCriticalFlagForPid(DWORD pid, ULONGLONG expectedCreationTime100ns, bool enable, std::wstring& message) {
    std::wstring privilegeDetail;
    (void)enableCurrentProcessPrivilege(SE_DEBUG_NAME, privilegeDetail);

    const FARPROC kProc = ntProc("NtSetInformationProcess");
    if (!kProc) {
        message = L"NtSetInformationProcess not available";
        return false;
    }

    std::wstring openError;
    ksword::core::UniqueHandle process = openProcessForAction(pid, expectedCreationTime100ns, PROCESS_SET_INFORMATION, openError);
    if (!process.valid()) {
        message = openError;
        return false;
    }

    ULONG critical = enable ? 1UL : 0UL;
    const LONG kStatus = reinterpret_cast<NtSetInformationProcessFn>(kProc)(
        process.get(),
        kProcessBreakOnTerminationInfoClass,
        &critical,
        static_cast<ULONG>(sizeof(critical)));
    if (kStatus >= 0) {
        message = privilegeDetail.empty() ? hex32(kStatus) : privilegeDetail + L"; " + hex32(kStatus);
        return true;
    }
    message = L"NtSetInformationProcess(ProcessBreakOnTermination) failed: " + hex32(kStatus);
    if (!privilegeDetail.empty()) {
        message += L"; " + privilegeDetail;
    }
    return false;
}

// setEfficiencyModeForPid toggles Windows process power throttling. Inputs are
// PID and target state; processing calls SetProcessInformation dynamically;
// output reports operation success and a concrete Win32 diagnostic.
bool setEfficiencyModeForPid(DWORD pid, ULONGLONG expectedCreationTime100ns, bool enable, std::wstring& message) {
    HMODULE kernel32 = ::GetModuleHandleW(L"kernel32.dll");
    const FARPROC kProc = kernel32 ? ::GetProcAddress(kernel32, "SetProcessInformation") : nullptr;
    if (!kProc) {
        message = L"SetProcessInformation(ProcessPowerThrottling) not available";
        return false;
    }

    std::wstring openError;
    ksword::core::UniqueHandle process = openProcessForAction(pid, expectedCreationTime100ns, PROCESS_SET_INFORMATION, openError);
    if (!process.valid()) {
        message = openError;
        return false;
    }

    ProcessPowerThrottlingStateNative powerState{};
    powerState.version = kProcessPowerThrottlingCurrentVersion;
    powerState.controlMask = kProcessPowerThrottlingExecutionSpeed;
    powerState.stateMask = enable ? kProcessPowerThrottlingExecutionSpeed : 0UL;
    const BOOL kOk = reinterpret_cast<SetProcessInformationFn>(kProc)(
        process.get(),
        kProcessPowerThrottlingInfoClass,
        &powerState,
        static_cast<DWORD>(sizeof(powerState)));
    if (kOk) {
        message = enable ? L"Efficiency mode enabled" : L"Efficiency mode disabled";
        return true;
    }
    message = L"SetProcessInformation(ProcessPowerThrottling) failed: " + win32ErrorText(::GetLastError());
    return false;
}

// protectionLevelForAction maps the menu protection commands to the one-byte
// PS_PROTECTION level accepted by IOCTL_KSWORD_ARK_SET_PPL_LEVEL. Input is a
// menu id; output is false when the id is not a protection command.
// The lower bits represent the type: 0x?1 indicates PPL (Light), and 0x?2 indicates full PP; the upper 4 bits represent the signer.
bool protectionLevelForAction(ProcessActionId actionId, std::uint8_t& levelOut) {
    switch (actionId) {
    case ProcessActionId::kR0SetPplNone: levelOut = 0x00; return true;
    case ProcessActionId::kR0SetPplAuthenticode: levelOut = 0x11; return true;
    case ProcessActionId::kR0SetPplCodeGen: levelOut = 0x21; return true;
    case ProcessActionId::kR0SetPplAntimalware: levelOut = 0x31; return true;
    case ProcessActionId::kR0SetPplLsa: levelOut = 0x41; return true;
    case ProcessActionId::kR0SetPplWindows: levelOut = 0x51; return true;
    case ProcessActionId::kR0SetPplWinTcb: levelOut = 0x61; return true;
    case ProcessActionId::kR0SetPpAuthenticode: levelOut = 0x12; return true;
    case ProcessActionId::kR0SetPpCodeGen: levelOut = 0x22; return true;
    case ProcessActionId::kR0SetPpAntimalware: levelOut = 0x32; return true;
    case ProcessActionId::kR0SetPpLsa: levelOut = 0x42; return true;
    case ProcessActionId::kR0SetPpWindows: levelOut = 0x52; return true;
    case ProcessActionId::kR0SetPpWinTcb: levelOut = 0x62; return true;
    default: levelOut = 0; return false;
    }
}

// integrityRidForAction maps the new R0 mandatory-label menu entries to the
// standard S-1-16-* RID values. Input is a context menu id; output is false when
// another action family should handle the command.
bool integrityRidForAction(ProcessActionId actionId, unsigned long& ridOut) {
    switch (actionId) {
    case ProcessActionId::kR0SetIntegrityUntrusted: ridOut = SECURITY_MANDATORY_UNTRUSTED_RID; return true;
    case ProcessActionId::kR0SetIntegrityLow: ridOut = SECURITY_MANDATORY_LOW_RID; return true;
    case ProcessActionId::kR0SetIntegrityMedium: ridOut = SECURITY_MANDATORY_MEDIUM_RID; return true;
    case ProcessActionId::kR0SetIntegrityMediumPlus: ridOut = SECURITY_MANDATORY_MEDIUM_PLUS_RID; return true;
    case ProcessActionId::kR0SetIntegrityHigh: ridOut = SECURITY_MANDATORY_HIGH_RID; return true;
    case ProcessActionId::kR0SetIntegritySystem: ridOut = SECURITY_MANDATORY_SYSTEM_RID; return true;
    default: ridOut = 0; return false;
    }
}

// integrityResultDetail renders the fixed response fields returned by
// DriverClient::setProcessIntegrity. Inputs are the parsed wrapper result;
// output is a compact Chinese/hex diagnostic for the context-menu status area.
std::wstring integrityResultDetail(const ksword::ark::ProcessIntegrityResult& io) {
    std::wostringstream stream;
    stream << utf8ToWide(io.io.message)
           << L"; status=" << io.status
           << L"; lastStatus=" << hex32(io.lastStatus)
           << L"; rid=0x" << std::hex << std::uppercase << io.integrityRid;
    if (io.unsupported) {
        stream << L"; unsupported";
    }
    return stream.str();
}

// injectResultDetail renders the R0 injection response without exposing any
// reusable primitive beyond what the driver already returned. Input is the
// ArkDriverClient parsed result; output is display-only status text.
std::wstring injectResultDetail(const ksword::ark::ProcessInjectResult& io) {
    std::wostringstream stream;
    stream << utf8ToWide(io.io.message)
           << L"; status=" << io.status
           << L"; lastStatus=" << hex32(io.lastStatus)
           << L"; waitStatus=" << hex32(io.waitStatus)
           << L"; bytesWritten=" << std::dec << io.bytesWritten
           << L"; remoteBase=" << hex64(io.remoteBaseAddress)
           << L"; entry=" << hex64(io.entryPointAddress);
    return stream.str();
}

// readBinaryFileForInjection loads a selected shellcode blob into memory. Input
// is a Win32 file path; processing enforces the shared R0 payload cap before
// returning bytes; output false includes a concrete diagnostic.
bool readBinaryFileForInjection(
    const std::wstring& path,
    std::vector<std::uint8_t>& bytes,
    std::wstring& errorText) {
    bytes.clear();
    if (path.empty()) {
        errorText = L"shellcode file path is empty";
        return false;
    }

    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file) {
        errorText = L"无法打开 shellcode 文件。";
        return false;
    }
    const std::streamoff kSize = file.tellg();
    if (kSize <= 0) {
        errorText = L"shellcode 文件为空。";
        return false;
    }
    if (static_cast<unsigned long long>(kSize) > KSWORD_ARK_PROCESS_INJECT_MAX_PAYLOAD_BYTES) {
        errorText = L"shellcode 文件超过 R0 注入协议上限 " +
            std::to_wstring(KSWORD_ARK_PROCESS_INJECT_MAX_PAYLOAD_BYTES) + L" 字节。";
        return false;
    }

    bytes.resize(static_cast<std::size_t>(kSize));
    file.seekg(0, std::ios::beg);
    if (!file.read(reinterpret_cast<char*>(bytes.data()), kSize)) {
        errorText = L"读取 shellcode 文件失败。";
        bytes.clear();
        return false;
    }
    return true;
}

// visibilityRequestForAction maps R0 process-hide menu ids onto the shared
// KswordArkProcessIoctl visibility action/flag contract. Input is a menu id;
// output is false when another action family should handle the command.
bool visibilityRequestForAction(ProcessActionId actionId, unsigned long& actionOut, unsigned long& flagsOut) {
    switch (actionId) {
    case ProcessActionId::kR0HideUnlinkOnly:
        actionOut = KSWORD_ARK_PROCESS_VISIBILITY_ACTION_HIDE;
        flagsOut = KSWORD_ARK_PROCESS_VISIBILITY_FLAG_UNLINK_ACTIVE_LIST;
        return true;
    case ProcessActionId::kR0HidePatchPidOnly:
        actionOut = KSWORD_ARK_PROCESS_VISIBILITY_ACTION_HIDE;
        flagsOut = KSWORD_ARK_PROCESS_VISIBILITY_FLAG_PATCH_UNIQUE_PID;
        return true;
    case ProcessActionId::kR0HideLegacyBoth:
        actionOut = KSWORD_ARK_PROCESS_VISIBILITY_ACTION_HIDE;
        flagsOut = KSWORD_ARK_PROCESS_VISIBILITY_FLAG_LEGACY_BOTH;
        return true;
    case ProcessActionId::kR0UnhideProcess:
        actionOut = KSWORD_ARK_PROCESS_VISIBILITY_ACTION_UNHIDE;
        flagsOut = 0;
        return true;
    case ProcessActionId::kR0ClearHiddenMarks:
        actionOut = KSWORD_ARK_PROCESS_VISIBILITY_ACTION_CLEAR_ALL;
        flagsOut = 0;
        return true;
    default:
        actionOut = 0;
        flagsOut = 0;
        return false;
    }
}

// specialProcessActionForMenu maps BreakOnTermination/APC menu entries onto
// IOCTL_KSWORD_ARK_SET_PROCESS_SPECIAL_FLAGS action values. Input is a menu id;
// output is false when the command belongs to another operation family.
bool specialProcessActionForMenu(ProcessActionId actionId, unsigned long& actionOut) {
    switch (actionId) {
    case ProcessActionId::kR0EnableBreakOnTermination:
        actionOut = KSWORD_ARK_PROCESS_SPECIAL_ACTION_ENABLE_BREAK_ON_TERMINATION;
        return true;
    case ProcessActionId::kR0DisableBreakOnTermination:
        actionOut = KSWORD_ARK_PROCESS_SPECIAL_ACTION_DISABLE_BREAK_ON_TERMINATION;
        return true;
    case ProcessActionId::kR0DisableApcInsertion:
        actionOut = KSWORD_ARK_PROCESS_SPECIAL_ACTION_DISABLE_APC_INSERTION;
        return true;
    default:
        actionOut = 0;
        return false;
    }
}

bool setPriorityForPid(
    DWORD pid,
    ULONGLONG expectedCreationTime100ns,
    DWORD priorityClass,
    std::wstring& detail) {
    std::wstring openError;
    ksword::core::UniqueHandle process = openProcessForAction(
        pid,
        expectedCreationTime100ns,
        PROCESS_SET_INFORMATION,
        openError);
    if (!process.valid()) {
        detail += L"PID " + std::to_wstring(pid) + L": " + openError + L"\r\n";
        return false;
    }
    const BOOL kOk = ::SetPriorityClass(process.get(), priorityClass);
    const DWORD kError = kOk ? ERROR_SUCCESS : ::GetLastError();
    detail += L"PID " + std::to_wstring(pid) + (kOk ? L": SetPriorityClass OK" : L": SetPriorityClass failed ") +
        (kOk ? L"" : std::to_wstring(kError)) + L"\r\n";
    return kOk != FALSE;
}

// keyboardEnumOk checks shared keyboard enumeration status values. Input is the
// R0 aggregate status; output accepts OK and PARTIAL because partial still gives
// usable rows for the UI.
bool keyboardEnumOk(std::uint32_t status) {
    return status == KSWORD_ARK_KEYBOARD_ENUM_STATUS_OK ||
        status == KSWORD_ARK_KEYBOARD_ENUM_STATUS_PARTIAL;
}

// executeKeyboardHotkeyScan queries R0 win32k hotkey/hook evidence for one
// process. Inputs are one captured process row; processing uses ArkDriverClient only;
// output is a ProcessActionResult suitable for the context menu status dialog.
ProcessActionResult executeKeyboardHotkeyScan(const ProcessSnapshotRow& target) {
    ProcessActionResult result;
    result.title = L"扫描进程热键";
    const DWORD kPid = target.processId;
    ksword::core::UniqueHandle identityHold;
    if (!holdProcessIdentityForDriverAction(target, L"scan hotkeys", false, result, identityHold)) {
        return result;
    }
    const ksword::ark::DriverClient kDriverClient;

    const ksword::ark::KeyboardHotkeyEnumResult kHotkeys = kDriverClient.enumerateKeyboardHotkeys(
        static_cast<std::uint32_t>(kPid),
        KSWORD_ARK_KEYBOARD_ENUM_FLAG_FILTER_PROCESS |
            KSWORD_ARK_KEYBOARD_ENUM_FLAG_INCLUDE_SYSTEM |
            KSWORD_ARK_KEYBOARD_ENUM_FLAG_INCLUDE_DIAGNOSTICS,
        2048UL);
    const ksword::ark::KeyboardHookEnumResult kHooks = kDriverClient.enumerateKeyboardHooks(
        static_cast<std::uint32_t>(kPid),
        KSWORD_ARK_KEYBOARD_ENUM_FLAG_FILTER_PROCESS |
            KSWORD_ARK_KEYBOARD_ENUM_FLAG_INCLUDE_THREAD_HOOKS |
            KSWORD_ARK_KEYBOARD_ENUM_FLAG_INCLUDE_GLOBAL_HOOKS |
            KSWORD_ARK_KEYBOARD_ENUM_FLAG_INCLUDE_DIAGNOSTICS,
        2048UL);

    const bool kHotkeyOk = kHotkeys.io.ok && keyboardEnumOk(kHotkeys.status);
    const bool kHookOk = kHooks.io.ok && keyboardEnumOk(kHooks.status);
    result.success = kHotkeyOk || kHookOk;

    std::wostringstream detail;
    detail << L"PID " << kPid << L"\r\n"
           << L"Hotkeys: IO=" << (kHotkeys.io.ok ? L"OK" : L"FAIL")
           << L", status=" << kHotkeys.status
           << L", total=" << kHotkeys.totalCount
           << L", returned=" << kHotkeys.returnedCount
           << L", parsed=" << kHotkeys.entries.size()
           << L", message=" << utf8ToWide(kHotkeys.io.message) << L"\r\n"
           << L"Hooks: IO=" << (kHooks.io.ok ? L"OK" : L"FAIL")
           << L", status=" << kHooks.status
           << L", total=" << kHooks.totalCount
           << L", returned=" << kHooks.returnedCount
           << L", parsed=" << kHooks.entries.size()
           << L", message=" << utf8ToWide(kHooks.io.message) << L"\r\n";

    const std::size_t kHotkeyLimit = std::min<std::size_t>(kHotkeys.entries.size(), 16U);
    for (std::size_t i = 0; i < kHotkeyLimit; ++i) {
        const ksword::ark::KeyboardHotkeyEntry& row = kHotkeys.entries[i];
        detail << L"Hotkey[" << i << L"] vk=0x" << std::hex << std::uppercase << row.virtualKey
               << L", modifiers=0x" << row.modifiers
               << L", tid=" << std::dec << row.threadId
               << L", object=" << hex64(row.hotkeyObject)
               << L", detail=" << row.detail << L"\r\n";
    }

    const std::size_t kHookLimit = std::min<std::size_t>(kHooks.entries.size(), 16U);
    for (std::size_t i = 0; i < kHookLimit; ++i) {
        const ksword::ark::KeyboardHookEntry& row = kHooks.entries[i];
        detail << L"Hook[" << i << L"] type=" << row.hookType
               << L", scope=" << row.hookScope
               << L", tid=" << row.threadId
               << L", proc=" << hex64(row.procedureAddress)
               << L", detail=" << row.detail << std::dec << L"\r\n";
    }

    result.detail = detail.str();
    return result;
}

// executeLocalProcessAction applies one local Win32/NtAPI action to captured
// process instances. Each helper validates the snapshot creation time on the
// same handle used by its mutation, so a reused PID is rejected.
ProcessActionResult executeLocalProcessAction(
    ProcessActionId actionId,
    const std::vector<ProcessSnapshotRow>& actionTargets) {
    ProcessActionResult result;
    result.success = true;
    bool handled = true;
    const wchar_t* operation = L"";
    switch (actionId) {
    case ProcessActionId::kSuspendProcess:
        result.title = L"挂起进程";
        operation = L"NtSuspendProcess";
        break;
    case ProcessActionId::kResumeProcess:
        result.title = L"恢复进程";
        operation = L"NtResumeProcess";
        break;
    case ProcessActionId::kEnableEfficiencyMode:
        result.title = L"开启效率模式";
        operation = L"Efficiency on";
        break;
    case ProcessActionId::kDisableEfficiencyMode:
        result.title = L"关闭效率模式";
        operation = L"Efficiency off";
        break;
    case ProcessActionId::kSetCriticalProcess:
        result.title = L"设为关键进程";
        operation = L"Critical on";
        break;
    case ProcessActionId::kClearCriticalProcess:
        result.title = L"取消关键进程";
        operation = L"Critical off";
        break;
    default:
        handled = false;
        break;
    }

    if (!handled) {
        result.success = false;
        result.title = L"进程动作";
        result.detail = L"未知本地进程动作。";
        return result;
    }

    for (const ProcessSnapshotRow& target : actionTargets) {
        const DWORD kPid = target.processId;
        const ULONGLONG kExpectedCreationTime100ns = target.creationTime100ns;
        std::wstring message;
        bool ok = false;
        switch (actionId) {
        case ProcessActionId::kSuspendProcess:
            ok = ntSuspendOrResumeProcess(kPid, kExpectedCreationTime100ns, false, message);
            break;
        case ProcessActionId::kResumeProcess:
            ok = ntSuspendOrResumeProcess(kPid, kExpectedCreationTime100ns, true, message);
            break;
        case ProcessActionId::kEnableEfficiencyMode:
            ok = setEfficiencyModeForPid(kPid, kExpectedCreationTime100ns, true, message);
            break;
        case ProcessActionId::kDisableEfficiencyMode:
            ok = setEfficiencyModeForPid(kPid, kExpectedCreationTime100ns, false, message);
            break;
        case ProcessActionId::kSetCriticalProcess:
            ok = setCriticalFlagForPid(kPid, kExpectedCreationTime100ns, true, message);
            break;
        case ProcessActionId::kClearCriticalProcess:
            ok = setCriticalFlagForPid(kPid, kExpectedCreationTime100ns, false, message);
            break;
        default:
            message = L"unknown action";
            ok = false;
            break;
        }
        appendIoLine(result.detail, kPid, operation, ok, message);
        result.success = result.success && ok;
    }
    return result;
}
// executePplRefresh queries the R0 process enumeration table and extracts the
// selected snapshot instances' protection bytes. Each verified handle remains
// live through the shared driver query so a recycled PID cannot supply results.
ProcessActionResult executePplRefresh(const std::vector<ProcessSnapshotRow>& actionTargets) {
    ProcessActionResult result;
    result.title = L"手动刷新PPL保护级别";
    result.success = true;

    std::vector<ProcessSnapshotRow> verifiedTargets;
    std::vector<ksword::core::UniqueHandle> identityHolds;
    verifiedTargets.reserve(actionTargets.size());
    identityHolds.reserve(actionTargets.size());
    for (const ProcessSnapshotRow& target : actionTargets) {
        ksword::core::UniqueHandle identityHold;
        if (!holdProcessIdentityForDriverAction(target, L"PPL refresh", false, result, identityHold)) {
            continue;
        }
        verifiedTargets.push_back(target);
        identityHolds.push_back(std::move(identityHold));
    }
    if (verifiedTargets.empty()) {
        return result;
    }

    const ksword::ark::DriverClient kDriverClient;
    const ksword::ark::ProcessEnumResult kQuery = kDriverClient.enumerateProcesses(0);
    if (!kQuery.io.ok) {
        result.success = false;
        result.detail = L"R0 process enumeration failed: " + utf8ToWide(kQuery.io.message);
        return result;
    }

    for (const ProcessSnapshotRow& target : verifiedTargets) {
        const DWORD kPid = target.processId;
        const auto kIt = std::find_if(kQuery.entries.begin(), kQuery.entries.end(), [kPid](const ksword::ark::ProcessEntry& row) {
            return row.processId == static_cast<std::uint32_t>(kPid);
        });
        if (kIt == kQuery.entries.end()) {
            appendIoLine(result.detail, kPid, L"PPL refresh", false, L"PID not returned by R0 enumeration");
            result.success = false;
            continue;
        }

        std::wostringstream line;
        line << L"protection=0x" << std::hex << std::uppercase << static_cast<unsigned int>(kIt->protection)
             << L", signature=0x" << static_cast<unsigned int>(kIt->signatureLevel)
             << L", sectionSignature=0x" << static_cast<unsigned int>(kIt->sectionSignatureLevel)
             << L", fieldFlags=0x" << kIt->fieldFlags
             << L", r0Status=" << std::dec << kIt->r0Status;
        const bool kHasProtection = (kIt->fieldFlags & KSWORD_ARK_PROCESS_FIELD_PROTECTION_PRESENT) != 0;
        appendIoLine(result.detail, kPid, L"PPL refresh", kHasProtection, line.str());
        result.success = result.success && kHasProtection;
    }
    return result;
}
} // namespace

ProcessActionResult executeProcessAction(
    ProcessActionId actionId,
    const std::vector<DWORD>& selectedPids,
    const std::vector<ProcessSnapshotRow>& snapshotRows) {
    if (selectedPids.empty() && actionId != ProcessActionId::kR0ClearHiddenMarks) {
        return failureResult(L"进程动作", selectedPids, L"没有选中进程。");
    }

    const auto kBuildActionTargets = [&snapshotRows](const std::vector<DWORD>& pids) {
        return buildProcessActionTargets(pids, snapshotRows);
    };

    const DWORD kPriorityClass = priorityClassForAction(actionId);
    if (kPriorityClass != 0) {
        ProcessActionResult result;
        result.title = L"设置进程优先级";
        result.success = true;
        for (const ProcessSnapshotRow& target : kBuildActionTargets(selectedPids)) {
            if (!setPriorityForPid(
                    target.processId,
                    target.creationTime100ns,
                    kPriorityClass,
                    result.detail)) {
                result.success = false;
            }
        }
        return result;
    }

    if (actionId == ProcessActionId::kOpenFolder) {
        const ProcessSnapshotRow* row = findRowByPid(snapshotRows, selectedPids.front());
        if (!row || row->imagePath.empty()) {
            return failureResult(L"打开所在目录", selectedPids, L"选中进程的映像路径不可用。");
        }
        const std::wstring kArgs = L"/select,\"" + row->imagePath + L"\"";
        const HINSTANCE kShellResult = ::ShellExecuteW(nullptr, L"open", L"explorer.exe", kArgs.c_str(), nullptr, SW_SHOWNORMAL);
        ProcessActionResult result;
        result.title = L"打开所在目录";
        result.success = reinterpret_cast<INT_PTR>(kShellResult) > 32;
        result.detail = result.success ? L"Explorer launch requested." : L"ShellExecuteW failed.";
        return result;
    }

    if (actionId == ProcessActionId::kTerminateProcessMultiMethod) {
        return executeMultiMethodTerminate(kBuildActionTargets(selectedPids));
    }

    if (actionId == ProcessActionId::kTerminateProcessTree) {
        const std::vector<DWORD> kTreePids = collectR3ProcessTreePids(selectedPids, snapshotRows);
        if (kTreePids.empty()) {
            return failureResult(L"结束进程树", selectedPids, L"选中进程未包含在当前 R3 进程快照中，无法识别进程树。");
        }
        ProcessActionResult result = executeMultiMethodTerminate(kBuildActionTargets(kTreePids));
        result.title = L"结束进程树";
        return result;
    }

    if (actionId == ProcessActionId::kTerminateProcess) {
        ProcessActionResult result;
        result.title = L"结束进程";
        result.success = true;
        for (const ProcessSnapshotRow& target : kBuildActionTargets(selectedPids)) {
            const DWORD kPid = target.processId;
            if (isProtectedSystemPid(kPid)) {
                appendIoLine(result.detail, kPid, L"TerminateProcess", false, L"protected system PID");
                result.success = false;
                continue;
            }
            std::wstring openError;
            ksword::core::UniqueHandle process = openProcessForAction(
                kPid,
                target.creationTime100ns,
                PROCESS_TERMINATE,
                openError);
            if (!process.valid()) {
                appendIoLine(result.detail, kPid, L"TerminateProcess", false, openError);
                result.success = false;
                continue;
            }
            const BOOL kOk = ::TerminateProcess(process.get(), static_cast<UINT>(0xC0000005u));
            const DWORD kError = kOk ? ERROR_SUCCESS : ::GetLastError();
            appendIoLine(result.detail, kPid, L"TerminateProcess", kOk != FALSE, kOk ? L"" : L"Win32 error " + std::to_wstring(kError));
            result.success = result.success && kOk != FALSE;
        }
        return result;
    }

    if (actionId == ProcessActionId::kR0TerminateProcess || actionId == ProcessActionId::kR0TerminateProcessTree) {
        const bool kTerminateTree = actionId == ProcessActionId::kR0TerminateProcessTree;
        const std::vector<DWORD> kTargetPids = kTerminateTree
            ? collectR3ProcessTreePids(selectedPids, snapshotRows)
            : selectedPids;
        if (kTargetPids.empty()) {
            return failureResult(L"R0结束进程树", selectedPids, L"选中进程未包含在当前 R3 进程快照中，无法识别进程树。");
        }
        ProcessActionResult result;
        result.title = kTerminateTree ? L"R0结束进程树" : L"R0结束进程";
        result.success = true;
        const ksword::ark::DriverClient kDriverClient;
        for (const ProcessSnapshotRow& target : kBuildActionTargets(kTargetPids)) {
            const DWORD kPid = target.processId;
            if (isProtectedSystemPid(kPid)) {
                appendIoLine(result.detail, kPid, L"R0 terminate", false, L"protected system PID");
                result.success = false;
                continue;
            }
            ksword::core::UniqueHandle identityHold;
            if (!holdProcessIdentityForDriverAction(target, L"R0 terminate", true, result, identityHold)) {
                continue;
            }
            // Each PID independently invokes ArkDriverClient, so it submits a separate IOCTL to terminate the existing process.
            const ksword::ark::IoResult kIo = kDriverClient.terminateProcess(static_cast<std::uint32_t>(kPid), static_cast<long>(0xC0000005u));
            appendIoLine(result.detail, kPid, L"R0 terminate", kIo.ok, utf8ToWide(kIo.message));
            result.success = result.success && kIo.ok;
        }
        return result;
    }

    if (actionId == ProcessActionId::kR0SuspendProcess) {
        ProcessActionResult result;
        result.title = L"R0挂起进程";
        result.success = true;
        const ksword::ark::DriverClient kDriverClient;
        for (const ProcessSnapshotRow& target : kBuildActionTargets(selectedPids)) {
            const DWORD kPid = target.processId;
            if (isProtectedSystemPid(kPid)) {
                appendIoLine(result.detail, kPid, L"R0 suspend", false, L"protected system PID");
                result.success = false;
                continue;
            }
            ksword::core::UniqueHandle identityHold;
            if (!holdProcessIdentityForDriverAction(target, L"R0 suspend", true, result, identityHold)) {
                continue;
            }
            const ksword::ark::IoResult kIo = kDriverClient.suspendProcess(static_cast<std::uint32_t>(kPid));
            appendIoLine(result.detail, kPid, L"R0 suspend", kIo.ok, utf8ToWide(kIo.message));
            result.success = result.success && kIo.ok;
        }
        return result;
    }

    std::uint8_t protectionLevel = 0;
    if (protectionLevelForAction(actionId, protectionLevel)) {
        ProcessActionResult result;
        result.title = L"R0设置PPL层级";
        result.success = true;
        const ksword::ark::DriverClient kDriverClient;
        for (const ProcessSnapshotRow& target : kBuildActionTargets(selectedPids)) {
            const DWORD kPid = target.processId;
            if (isProtectedSystemPid(kPid)) {
                appendIoLine(result.detail, kPid, L"set PPL", false, L"protected system PID");
                result.success = false;
                continue;
            }
            ksword::core::UniqueHandle identityHold;
            if (!holdProcessIdentityForDriverAction(target, L"set PPL", true, result, identityHold)) {
                continue;
            }
            const ksword::ark::IoResult kIo = kDriverClient.setProcessProtection(static_cast<std::uint32_t>(kPid), protectionLevel);
            appendIoLine(result.detail, kPid, L"set PPL", kIo.ok, utf8ToWide(kIo.message));
            result.success = result.success && kIo.ok;
        }
        return result;
    }

    unsigned long integrityRid = 0;
    if (integrityRidForAction(actionId, integrityRid)) {
        ProcessActionResult result;
        result.title = L"R0设置进程完整性";
        result.success = true;
        const ksword::ark::DriverClient kDriverClient;
        for (const ProcessSnapshotRow& target : kBuildActionTargets(selectedPids)) {
            const DWORD kPid = target.processId;
            if (isProtectedSystemPid(kPid)) {
                appendIoLine(result.detail, kPid, L"set integrity", false, L"protected system PID");
                result.success = false;
                continue;
            }
            ksword::core::UniqueHandle identityHold;
            if (!holdProcessIdentityForDriverAction(target, L"set integrity", true, result, identityHold)) {
                continue;
            }
            const ksword::ark::ProcessIntegrityResult kIo =
                kDriverClient.setProcessIntegrity(static_cast<std::uint32_t>(kPid), integrityRid);
            const bool kOk = kIo.io.ok &&
                !kIo.unsupported &&
                kIo.lastStatus >= 0 &&
                kIo.status == KSWORD_ARK_PROCESS_INTEGRITY_STATUS_APPLIED;
            appendIoLine(result.detail, kPid, L"set integrity", kOk, integrityResultDetail(kIo));
            result.success = result.success && kOk;
        }
        return result;
    }

    unsigned long visibilityAction = 0;
    unsigned long visibilityFlags = 0;
    if (visibilityRequestForAction(actionId, visibilityAction, visibilityFlags)) {
        ProcessActionResult result;
        result.title = L"R0进程可见性";
        result.success = true;
        const ksword::ark::DriverClient kDriverClient;
        if (actionId == ProcessActionId::kR0ClearHiddenMarks) {
            const ksword::ark::ProcessVisibilityResult kIo = kDriverClient.setProcessVisibility(0, visibilityAction, visibilityFlags);
            const bool kOk = kIo.io.ok && kIo.lastStatus >= 0 && kIo.status == KSWORD_ARK_PROCESS_VISIBILITY_STATUS_CLEARED;
            appendIoLine(result.detail, L"R0 clear hidden marks", kOk, utf8ToWide(kIo.io.message));
            result.success = kOk;
            return result;
        }
        for (const ProcessSnapshotRow& target : kBuildActionTargets(selectedPids)) {
            const DWORD kPid = target.processId;
            if (visibilityAction == KSWORD_ARK_PROCESS_VISIBILITY_ACTION_HIDE && isProtectedSystemPid(kPid)) {
                appendIoLine(result.detail, kPid, L"visibility", false, L"protected system PID");
                result.success = false;
                continue;
            }
            ksword::core::UniqueHandle identityHold;
            if (!holdProcessIdentityForDriverAction(
                    target,
                    L"visibility",
                    visibilityAction == KSWORD_ARK_PROCESS_VISIBILITY_ACTION_HIDE,
                    result,
                    identityHold)) {
                continue;
            }
            const ksword::ark::ProcessVisibilityResult kIo = kDriverClient.setProcessVisibility(static_cast<std::uint32_t>(kPid), visibilityAction, visibilityFlags);
            const bool kOk = kIo.io.ok && kIo.lastStatus >= 0 &&
                (kIo.status == KSWORD_ARK_PROCESS_VISIBILITY_STATUS_HIDDEN ||
                 kIo.status == KSWORD_ARK_PROCESS_VISIBILITY_STATUS_VISIBLE ||
                 kIo.status == KSWORD_ARK_PROCESS_VISIBILITY_STATUS_CLEARED);
            appendIoLine(result.detail, kPid, L"visibility", kOk, utf8ToWide(kIo.io.message));
            result.success = result.success && kOk;
        }
        return result;
    }

    unsigned long specialAction = 0;
    if (specialProcessActionForMenu(actionId, specialAction)) {
        ProcessActionResult result;
        result.title = L"R0进程特殊标志";
        result.success = true;
        const ksword::ark::DriverClient kDriverClient;
        for (const ProcessSnapshotRow& target : kBuildActionTargets(selectedPids)) {
            const DWORD kPid = target.processId;
            if (isProtectedSystemPid(kPid)) {
                appendIoLine(result.detail, kPid, L"special flags", false, L"protected system PID");
                result.success = false;
                continue;
            }
            ksword::core::UniqueHandle identityHold;
            if (!holdProcessIdentityForDriverAction(target, L"special flags", true, result, identityHold)) {
                continue;
            }
            const ksword::ark::ProcessSpecialFlagsResult kIo = kDriverClient.setProcessSpecialFlags(static_cast<std::uint32_t>(kPid), specialAction);
            const bool kOk = kIo.io.ok && kIo.lastStatus >= 0 && kIo.status == KSWORD_ARK_PROCESS_SPECIAL_STATUS_APPLIED;
            appendIoLine(result.detail, kPid, L"special flags", kOk, utf8ToWide(kIo.io.message));
            result.success = result.success && kOk;
        }
        return result;
    }

    if (actionId == ProcessActionId::kR0DkomRemoveFromCidTable) {
        ProcessActionResult result;
        result.title = L"R0 DKOM从PspCidTable删除";
        result.success = true;
        const ksword::ark::DriverClient kDriverClient;
        for (const ProcessSnapshotRow& target : kBuildActionTargets(selectedPids)) {
            const DWORD kPid = target.processId;
            if (isProtectedSystemPid(kPid)) {
                appendIoLine(result.detail, kPid, L"DKOM CID remove", false, L"protected system PID");
                result.success = false;
                continue;
            }
            ksword::core::UniqueHandle identityHold;
            if (!holdProcessIdentityForDriverAction(target, L"DKOM CID remove", true, result, identityHold)) {
                continue;
            }
            const ksword::ark::ProcessDkomResult kIo = kDriverClient.dkomProcess(static_cast<std::uint32_t>(kPid), KSWORD_ARK_PROCESS_DKOM_ACTION_REMOVE_FROM_PSP_CID_TABLE);
            const bool kOk = kIo.io.ok && kIo.lastStatus >= 0 && kIo.status == KSWORD_ARK_PROCESS_DKOM_STATUS_REMOVED && kIo.removedEntries > 0;
            appendIoLine(result.detail, kPid, L"DKOM CID remove", kOk, utf8ToWide(kIo.io.message));
            result.success = result.success && kOk;
        }
        return result;
    }

    switch (actionId) {
    case ProcessActionId::kSuspendProcess:
    case ProcessActionId::kResumeProcess:
    case ProcessActionId::kEnableEfficiencyMode:
    case ProcessActionId::kDisableEfficiencyMode:
    case ProcessActionId::kSetCriticalProcess:
    case ProcessActionId::kClearCriticalProcess:
        return executeLocalProcessAction(actionId, kBuildActionTargets(selectedPids));
    case ProcessActionId::kRefreshPplProtectionLevel:
        return executePplRefresh(kBuildActionTargets(selectedPids));
    case ProcessActionId::kOpenMemoryOperation: {
        ProcessActionResult result;
        result.title = L"复制到内存读写页输入";
        const std::wstring kPidText = pidListText(selectedPids);
        result.success = writeClipboardText(nullptr, kPidText);
        result.detail = result.success
            ? L"已复制 PID 列表，可粘贴到驱动内存读写页的目标 PID 输入框: " + kPidText
            : L"复制 PID 列表到剪贴板失败: " + win32ErrorText(::GetLastError());
        return result;
    }
    case ProcessActionId::kScanHotkeys:
        if (selectedPids.size() != 1) {
            return failureResult(L"扫描进程热键", selectedPids, L"扫描进程热键需要单选一个进程。");
        }
        {
            const std::vector<ProcessSnapshotRow> kActionTargets = kBuildActionTargets(selectedPids);
            if (kActionTargets.size() != 1U) {
                return failureResult(L"扫描进程热键", selectedPids, L"扫描进程热键需要单选一个进程。");
            }
            return executeKeyboardHotkeyScan(kActionTargets.front());
        }
    case ProcessActionId::kOpenDetails:
        return failureResult(L"进程详细信息", selectedPids, L"该动作由进程列表窗口直接打开详细信息页。");
    default:
        return failureResult(L"进程动作", selectedPids, L"未知进程动作。");
    }
}

ProcessActionResult executeR0ProcessDllInjection(
    const std::vector<DWORD>& selectedPids,
    const std::vector<ProcessSnapshotRow>& snapshotRows,
    const std::wstring& dllPath) {
    if (selectedPids.size() != 1) {
        return failureResult(L"R0 DLL注入", selectedPids, L"R0 DLL 注入需要单选一个进程。");
    }
    if (dllPath.empty()) {
        return failureResult(L"R0 DLL注入", selectedPids, L"未选择 DLL 文件。");
    }

    const std::vector<ProcessSnapshotRow> kActionTargets = buildProcessActionTargets(selectedPids, snapshotRows);
    if (kActionTargets.size() != 1U) {
        return failureResult(L"R0 DLL注入", selectedPids, L"R0 DLL 注入需要单选一个进程。");
    }

    ProcessActionResult result;
    result.title = L"R0 DLL注入";
    const ProcessSnapshotRow& target = kActionTargets.front();
    const DWORD kPid = target.processId;
    if (isProtectedSystemPid(kPid)) {
        result.success = false;
        appendIoLine(result.detail, kPid, L"inject DLL", false, L"protected system PID");
        return result;
    }
    ksword::core::UniqueHandle identityHold;
    if (!holdProcessIdentityForDriverAction(target, L"inject DLL", true, result, identityHold)) {
        return result;
    }

    const ksword::ark::DriverClient kDriverClient;
    const ksword::ark::ProcessInjectResult kIo = kDriverClient.injectProcessDll(
        static_cast<std::uint32_t>(kPid),
        dllPath,
        KSWORD_ARK_PROCESS_INJECT_FLAG_UI_CONFIRMED | KSWORD_ARK_PROCESS_INJECT_FLAG_WAIT_THREAD);
    result.success = kIo.io.ok &&
        kIo.lastStatus >= 0 &&
        kIo.status == KSWORD_ARK_PROCESS_INJECT_STATUS_INJECTED;
    appendIoLine(result.detail, kPid, L"inject DLL", result.success, injectResultDetail(kIo));
    return result;
}

ProcessActionResult executeR0ProcessShellcodeInjection(
    const std::vector<DWORD>& selectedPids,
    const std::vector<ProcessSnapshotRow>& snapshotRows,
    const std::wstring& shellcodePath) {
    if (selectedPids.size() != 1) {
        return failureResult(L"R0 Shellcode注入", selectedPids, L"R0 Shellcode 注入需要单选一个进程。");
    }

    std::vector<std::uint8_t> shellcode;
    std::wstring readError;
    if (!readBinaryFileForInjection(shellcodePath, shellcode, readError)) {
        return failureResult(L"R0 Shellcode注入", selectedPids, readError.c_str());
    }

    const std::vector<ProcessSnapshotRow> kActionTargets = buildProcessActionTargets(selectedPids, snapshotRows);
    if (kActionTargets.size() != 1U) {
        return failureResult(L"R0 Shellcode注入", selectedPids, L"R0 Shellcode 注入需要单选一个进程。");
    }

    ProcessActionResult result;
    result.title = L"R0 Shellcode注入";
    const ProcessSnapshotRow& target = kActionTargets.front();
    const DWORD kPid = target.processId;
    if (isProtectedSystemPid(kPid)) {
        result.success = false;
        appendIoLine(result.detail, kPid, L"inject shellcode", false, L"protected system PID");
        return result;
    }
    ksword::core::UniqueHandle identityHold;
    if (!holdProcessIdentityForDriverAction(target, L"inject shellcode", true, result, identityHold)) {
        return result;
    }

    const ksword::ark::DriverClient kDriverClient;
    const ksword::ark::ProcessInjectResult kIo = kDriverClient.injectProcessShellcode(
        static_cast<std::uint32_t>(kPid),
        shellcode,
        KSWORD_ARK_PROCESS_INJECT_FLAG_UI_CONFIRMED);
    result.success = kIo.io.ok &&
        kIo.lastStatus >= 0 &&
        kIo.status == KSWORD_ARK_PROCESS_INJECT_STATUS_INJECTED;
    appendIoLine(result.detail, kPid, L"inject shellcode", result.success, injectResultDetail(kIo));
    return result;
}

DWORD priorityClassForAction(ProcessActionId actionId) {
    switch (actionId) {
    case ProcessActionId::kSetPriorityIdle: return IDLE_PRIORITY_CLASS;
    case ProcessActionId::kSetPriorityBelowNormal: return BELOW_NORMAL_PRIORITY_CLASS;
    case ProcessActionId::kSetPriorityNormal: return NORMAL_PRIORITY_CLASS;
    case ProcessActionId::kSetPriorityAboveNormal: return ABOVE_NORMAL_PRIORITY_CLASS;
    case ProcessActionId::kSetPriorityHigh: return HIGH_PRIORITY_CLASS;
    case ProcessActionId::kSetPriorityRealtime: return REALTIME_PRIORITY_CLASS;
    default: return 0;
    }
}

} // namespace Ksword::Features::Process

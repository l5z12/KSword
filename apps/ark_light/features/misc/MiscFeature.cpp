#include "MiscFeature.h"

#include "../../ui/AsyncTask.h"
#include "../../ui/Controls.h"
#include "../../ui/FilterBar.h"
#include "../../ui/ListViewUtil.h"
#include "../../ui/LoadingOverlay.h"
#include "../../ui/TabUtil.h"
#include "../../ui/Theme.h"
#include "../../ui/VirtualListView.h"
#include "../../../../shared/ark_client/ArkDriverClient.h"

#include <commctrl.h>
#include <windowsx.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <cwctype>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace ksword::features::misc {
namespace {

constexpr wchar_t kMiscHostClass[] = L"KswordARKLight.MiscFeaturePage";
constexpr wchar_t kMiscAuditViewClass[] = L"KswordARKLight.MiscAuditView";
constexpr int kTabId = 69101;
constexpr int kListId = 69102;
constexpr int kRefreshButtonId = 69103;
constexpr int kCopyButtonId = 69104;
constexpr int kFilterBarId = 69105;
constexpr int kLoadingOverlayId = 69106;
constexpr int kBugcheckUploadButtonId = 69107;
constexpr int kCiTabIndex = 0;
constexpr int kVbsTabIndex = 1;
constexpr int kHyperVTabIndex = 2;
constexpr int kAppLockerTabIndex = 3;
constexpr int kAuxiliaryTabIndex = 4;
constexpr int kBugcheckTabIndex = 5;
constexpr int kHeaderHeight = 68;
constexpr int kGap = 6;
constexpr UINT kMenuRefresh = 69201;
constexpr UINT kMenuCopyRow = 69202;
constexpr UINT kMenuCopyAll = 69203;
constexpr UINT kMenuCopyCell = 69204;
constexpr UINT kMsgAuditRefreshCompleted = WM_APP + 603;
constexpr UINT kMsgAuditFilterCompleted = WM_APP + 604;
constexpr UINT kMsgBugcheckUploadCompleted = WM_APP + 605;

enum class MiscAuditPageId {
    kCodeIntegrity,
    kVbsHvciSkci,
    kHyperV,
    kAppLocker,
    kBamAhcache,
    kBugcheck,
};

// MiscAuditRow is the value-only evidence record rendered into each ListView.
// Inputs come from read-only R3 commands, registry reads, service status queries
// and ArkDriverClient diagnostics. Processing stores only display strings;
// output is consumed by populateAuditList and clipboard export helpers.
struct MiscAuditRow {
    std::wstring category;
    std::wstring item;
    std::wstring state;
    std::wstring source;
    std::wstring risk;
    std::wstring detail;
};

struct MiscAuditRefreshResult {
    MiscAuditPageId pageId = MiscAuditPageId::kCodeIntegrity;
    std::vector<MiscAuditRow> rows;
};

struct MiscAuditFilterResult {
    std::uint64_t generation = 0;
    std::wstring query;
    bool useRegex = false;
    std::vector<std::size_t> visibleIndexes;
};

// BugcheckUploadResult holds the value-only transport outcome of the explicit
// VMware diagnostic branding upload. It deliberately carries no bitmap bytes.
struct BugcheckUploadResult {
    ksword::ark::IoResult io;
};

// CommandResult captures bounded stdout/stderr from an external read-only query.
// Inputs are filled by runCaptureCommand; processing later turns exit code and
// captured text into UI rows. No handles are retained after the command returns.
struct CommandResult {
    bool started = false;
    DWORD exitCode = ERROR_PROCESS_ABORTED;
    DWORD win32Error = ERROR_SUCCESS;
    std::wstring output;
    std::wstring errorText;
};

// MiscAuditViewState owns one tab page and its row snapshot. Inputs arrive from
// Win32 messages; processing refreshes only the local page and never performs
// patch/delete/bypass/remove/unlink operations. There is no shared global state.
struct MiscAuditViewState {
    HWND hwnd = nullptr;
    HWND refreshButton = nullptr;
    HWND copyButton = nullptr;
    HWND bugcheckUploadButton = nullptr;
    HWND filterBar = nullptr;
    HWND list = nullptr;
    HWND loadingOverlay = nullptr;
    MiscAuditPageId pageId = MiscAuditPageId::kCodeIntegrity;
    std::wstring title;
    std::wstring statusText;
    std::vector<MiscAuditRow> rows;
    std::vector<MiscAuditRow> visibleRows;
    ksword::ui::VirtualListView virtualList;
    std::shared_ptr<const std::vector<ksword::ui::VirtualListRow>> filterRows;
    std::wstring filterQuery;
    bool filterUseRegex = false;
    std::uint64_t snapshotGeneration = 0;
    int contextColumn = 0;
    bool hasLoaded = false;
    std::unique_ptr<ksword::ui::AsyncSnapshotTask<MiscAuditRefreshResult>> refreshTask;
    std::unique_ptr<ksword::ui::AsyncSnapshotTask<MiscAuditFilterResult>> filterTask;
    std::unique_ptr<ksword::ui::AsyncSnapshotTask<BugcheckUploadResult>> bugcheckUploadTask;
};

// MiscFeaturePageState owns the tab host and retained child pages. Inputs arrive
// through the host window procedure; processing switches visibility only, so each
// tab keeps its last snapshot and diagnostics until explicitly refreshed.
struct MiscFeaturePageState {
    HWND hwnd = nullptr;
    HWND tab = nullptr;
    HWND ciView = nullptr;
    HWND vbsView = nullptr;
    HWND hypervView = nullptr;
    HWND appLockerView = nullptr;
    HWND auxiliaryView = nullptr;
    HWND bugcheckView = nullptr;
    int currentTab = kCiTabIndex;
};

// Width returns a non-negative RECT width. Input is a Win32 RECT; output is the
// client width used by layout code.
int width(const RECT& rc) {
    return rc.right > rc.left ? rc.right - rc.left : 0;
}

// Height returns a non-negative RECT height. Input is a Win32 RECT; output is
// the client height used by layout code.
int height(const RECT& rc) {
    return rc.bottom > rc.top ? rc.bottom - rc.top : 0;
}

// stateFromAuditView reads the MiscAuditViewState pointer from a child HWND.
// Input is the page HWND; output is null before WM_NCCREATE or after destroy.
MiscAuditViewState* stateFromAuditView(HWND hwnd) {
    return reinterpret_cast<MiscAuditViewState*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
}

// stateFromHost reads the MiscFeaturePageState pointer from the host HWND. Input
// is the host HWND; output is null before creation or after destruction.
MiscFeaturePageState* stateFromHost(HWND hwnd) {
    return reinterpret_cast<MiscFeaturePageState*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
}

// TrimCopy removes leading and trailing whitespace from display command output.
// Input is any captured string; processing does not alter interior newlines;
// output is a new trimmed string.
std::wstring trimCopy(const std::wstring& text) {
    std::size_t begin = 0;
    while (begin < text.size() && std::iswspace(text[begin])) {
        ++begin;
    }
    std::size_t end = text.size();
    while (end > begin && std::iswspace(text[end - 1])) {
        --end;
    }
    return text.substr(begin, end - begin);
}

// collapseWhitespace converts multi-line command output into compact cell text.
// Input is a captured string; processing replaces CR/LF/TAB runs with spaces;
// output is bounded by the caller when inserted into the ListView.
std::wstring collapseWhitespace(const std::wstring& text) {
    std::wstring out;
    bool inWhitespace = false;
    for (wchar_t ch : text) {
        if (std::iswspace(ch)) {
            if (!inWhitespace && !out.empty()) {
                out.push_back(L' ');
            }
            inWhitespace = true;
            continue;
        }
        inWhitespace = false;
        out.push_back(ch);
    }
    return trimCopy(out);
}

// quotePowerShellCommand wraps a script body in a PowerShell script block.
// Input is one read-only command body; processing keeps the body executable by
// powershell.exe while avoiding cmd.exe parsing; output is used only locally.
std::wstring quotePowerShellCommand(const std::wstring& text) {
    return L"\"& { " + text + L" }\"";
}

// getLastErrorText formats a Win32 error. Input is a DWORD error code; output is
// a readable message with the numeric value retained for diagnostics.
std::wstring getLastErrorText(const DWORD error) {
    if (error == 0) {
        return L"0";
    }
    wchar_t* message = nullptr;
    const DWORD kFlags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
    const DWORD kChars = ::FormatMessageW(kFlags, nullptr, error, 0, reinterpret_cast<LPWSTR>(&message), 0, nullptr);
    std::wstring result = L"Win32=" + std::to_wstring(error);
    if (kChars != 0 && message) {
        result += L" (" + trimCopy(message) + L")";
    }
    if (message) {
        ::LocalFree(message);
    }
    return result;
}

// appendRow appends one evidence row to a vector. Inputs are display fields and
// optional detail; processing copies them into the row list; no value is returned.
void appendRow(
    std::vector<MiscAuditRow>& rows,
    std::wstring category,
    std::wstring item,
    std::wstring state,
    std::wstring source,
    std::wstring risk,
    std::wstring detail) {
    rows.push_back(MiscAuditRow{
        std::move(category),
        std::move(item),
        std::move(state),
        std::move(source),
        std::move(risk),
        std::move(detail),
    });
}

// runCaptureCommand starts a bounded child process and captures stdout/stderr.
// Inputs are the full command line and timeout in milliseconds; processing uses
// anonymous pipes, waits without injecting input, and terminates only the helper
// process if it exceeds the local UI budget; output includes failure reason.
CommandResult runCaptureCommand(const std::wstring& commandLine, const DWORD timeoutMs = 12000) {
    CommandResult result;
    SECURITY_ATTRIBUTES security{};
    security.nLength = sizeof(security);
    security.bInheritHandle = TRUE;

    HANDLE readPipe = nullptr;
    HANDLE writePipe = nullptr;
    if (!::CreatePipe(&readPipe, &writePipe, &security, 0)) {
        result.win32Error = ::GetLastError();
        result.errorText = L"CreatePipe failed: " + getLastErrorText(result.win32Error);
        return result;
    }
    ::SetHandleInformation(readPipe, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    startup.wShowWindow = SW_HIDE;
    startup.hStdOutput = writePipe;
    startup.hStdError = writePipe;
    startup.hStdInput = ::GetStdHandle(STD_INPUT_HANDLE);

    PROCESS_INFORMATION process{};
    std::wstring mutableCommand = commandLine;
    const BOOL kCreated = ::CreateProcessW(
        nullptr,
        mutableCommand.data(),
        nullptr,
        nullptr,
        TRUE,
        CREATE_NO_WINDOW,
        nullptr,
        nullptr,
        &startup,
        &process);
    ::CloseHandle(writePipe);

    if (!kCreated) {
        result.win32Error = ::GetLastError();
        result.errorText = L"CreateProcessW failed: " + getLastErrorText(result.win32Error);
        ::CloseHandle(readPipe);
        return result;
    }

    result.started = true;
    std::string bytes;
    std::array<char, 4096> buffer{};
    const ULONGLONG kDeadline = ::GetTickCount64() + timeoutMs;
    bool processFinished = false;
    bool outputLimitHit = false;
    while (!processFinished) {
        DWORD available = 0;
        while (!outputLimitHit &&
            ::PeekNamedPipe(readPipe, nullptr, 0, nullptr, &available, nullptr) &&
            available > 0) {
            DWORD read = 0;
            const DWORD kChunk = std::min<DWORD>(available, static_cast<DWORD>(buffer.size()));
            if (!::ReadFile(readPipe, buffer.data(), kChunk, &read, nullptr) || read == 0) {
                break;
            }
            bytes.append(buffer.data(), buffer.data() + read);
            if (bytes.size() > 128 * 1024) {
                result.errorText += L" 输出超过 128KB，已截断。";
                outputLimitHit = true;
                break;
            }
        }

        const DWORD kWait = ::WaitForSingleObject(process.hProcess, 25);
        if (kWait == WAIT_OBJECT_0) {
            processFinished = true;
        } else if (kWait == WAIT_FAILED) {
            result.win32Error = ::GetLastError();
            result.errorText = L"WaitForSingleObject failed: " + getLastErrorText(result.win32Error);
            processFinished = true;
        } else if (::GetTickCount64() >= kDeadline) {
            ::TerminateProcess(process.hProcess, 258);
            result.exitCode = 258;
            result.errorText = L"查询超时，已停止本地只读辅助进程。";
            processFinished = true;
        }
    }

    if (!outputLimitHit) {
        DWORD available = 0;
        while (::PeekNamedPipe(readPipe, nullptr, 0, nullptr, &available, nullptr) && available > 0) {
            DWORD read = 0;
            const DWORD kChunk = std::min<DWORD>(available, static_cast<DWORD>(buffer.size()));
            if (!::ReadFile(readPipe, buffer.data(), kChunk, &read, nullptr) || read == 0) {
                break;
            }
            bytes.append(buffer.data(), buffer.data() + read);
            if (bytes.size() > 128 * 1024) {
                result.errorText += L" 输出超过 128KB，已截断。";
                break;
            }
        }
    }

    DWORD exitCode = ERROR_PROCESS_ABORTED;
    if (::GetExitCodeProcess(process.hProcess, &exitCode)) {
        result.exitCode = exitCode;
    }
    else {
        const DWORD kExitCodeError = ::GetLastError();
        if (result.win32Error == ERROR_SUCCESS) {
            result.win32Error = kExitCodeError;
        }
        if (result.errorText.empty()) {
            result.errorText = getLastErrorText(kExitCodeError);
        }
    }
    if (result.exitCode == STILL_ACTIVE) {
        result.exitCode = 258;
    }

    if (!bytes.empty()) {
        const int kRequired = ::MultiByteToWideChar(CP_UTF8, 0, bytes.data(), static_cast<int>(bytes.size()), nullptr, 0);
        if (kRequired > 0) {
            result.output.assign(static_cast<std::size_t>(kRequired), L'\0');
            ::MultiByteToWideChar(CP_UTF8, 0, bytes.data(), static_cast<int>(bytes.size()), result.output.data(), kRequired);
        } else {
            const int kFallback = ::MultiByteToWideChar(CP_ACP, 0, bytes.data(), static_cast<int>(bytes.size()), nullptr, 0);
            if (kFallback > 0) {
                result.output.assign(static_cast<std::size_t>(kFallback), L'\0');
                ::MultiByteToWideChar(CP_ACP, 0, bytes.data(), static_cast<int>(bytes.size()), result.output.data(), kFallback);
            }
        }
    }

    ::CloseHandle(readPipe);
    ::CloseHandle(process.hThread);
    ::CloseHandle(process.hProcess);
    return result;
}

// powerShellCommand builds a hidden, non-profile PowerShell invocation for local
// read-only posture queries. Input is a script body; output is a command line for
// runCaptureCommand. The script is expected to avoid mutation cmdlets.
std::wstring powerShellCommand(const std::wstring& script) {
    return L"powershell.exe -NoLogo -NoProfile -NonInteractive -Command " +
        quotePowerShellCommand(script);
}

// runPowerShellScalar executes one PowerShell query and returns compact output.
// Inputs are a script body and timeout; processing captures stdout/stderr and
// keeps the failure reason if PowerShell/WMI is unavailable; output is a command
// result suitable for addCommandRow.
CommandResult runPowerShellScalar(const std::wstring& script, const DWORD timeoutMs = 12000) {
    return runCaptureCommand(powerShellCommand(script), timeoutMs);
}

// addCommandRow converts a command result into one evidence row. Inputs identify
// the evidence and command source; processing stores either output or an explicit
// failure reason; no value is returned.
void addCommandRow(
    std::vector<MiscAuditRow>& rows,
    const std::wstring& category,
    const std::wstring& item,
    const std::wstring& source,
    const CommandResult& command,
    const std::wstring& cleanHint = L"已查询") {
    const std::wstring kOutput = collapseWhitespace(command.output);
    if (command.started
        && command.win32Error == ERROR_SUCCESS
        && command.errorText.empty()
        && command.exitCode == 0
        && !kOutput.empty()) {
        appendRow(rows, category, item, cleanHint, source, L"Info", kOutput);
        return;
    }

    std::wstring detail = command.errorText;
    if (!kOutput.empty()) {
        if (!detail.empty()) {
            detail += L" ";
        }
        detail += kOutput;
    }
    if (detail.empty()) {
        detail = command.started
            ? (L"查询进程退出码=" + std::to_wstring(command.exitCode))
            : (L"查询未启动，" + getLastErrorText(command.win32Error));
    }
    appendRow(rows, category, item, L"Unavailable", source, L"Unknown", detail);
}

// queryRegistryValueString reads one HKLM value without writing registry state.
// Inputs are a subkey and value name; processing uses RegOpenKeyEx/RegQueryValueEx
// with KEY_READ only; output is true when a display value was extracted.
bool queryRegistryValueString(const std::wstring& subKey, const std::wstring& valueName, std::wstring& valueOut, std::wstring& errorOut) {
    HKEY key = nullptr;
    const LONG kOpen = ::RegOpenKeyExW(HKEY_LOCAL_MACHINE, subKey.c_str(), 0, KEY_READ | KEY_WOW64_64KEY, &key);
    if (kOpen != ERROR_SUCCESS) {
        errorOut = L"RegOpenKeyExW failed: " + getLastErrorText(static_cast<DWORD>(kOpen));
        return false;
    }

    DWORD type = 0;
    DWORD bytes = 0;
    LONG query = ::RegQueryValueExW(key, valueName.c_str(), nullptr, &type, nullptr, &bytes);
    if (query != ERROR_SUCCESS) {
        ::RegCloseKey(key);
        errorOut = L"RegQueryValueExW(size) failed: " + getLastErrorText(static_cast<DWORD>(query));
        return false;
    }

    std::vector<unsigned char> data(std::max<DWORD>(bytes, sizeof(wchar_t)) + sizeof(wchar_t), 0);
    query = ::RegQueryValueExW(key, valueName.c_str(), nullptr, &type, data.data(), &bytes);
    ::RegCloseKey(key);
    if (query != ERROR_SUCCESS) {
        errorOut = L"RegQueryValueExW(data) failed: " + getLastErrorText(static_cast<DWORD>(query));
        return false;
    }

    if (type == REG_DWORD && bytes >= sizeof(DWORD)) {
        DWORD value = 0;
        std::memcpy(&value, data.data(), sizeof(value));
        valueOut = std::to_wstring(value) + L" (0x";
        std::wostringstream stream;
        stream << std::hex << std::uppercase << value;
        valueOut += stream.str() + L")";
        return true;
    }
    if ((type == REG_SZ || type == REG_EXPAND_SZ) && bytes >= sizeof(wchar_t)) {
        valueOut.assign(reinterpret_cast<const wchar_t*>(data.data()));
        return true;
    }
    if (type == REG_MULTI_SZ && bytes >= sizeof(wchar_t)) {
        const wchar_t* multi = reinterpret_cast<const wchar_t*>(data.data());
        const std::size_t kChars = bytes / sizeof(wchar_t);
        std::wstring joined;
        std::size_t offset = 0;
        while (offset < kChars && multi[offset] != L'\0') {
            std::wstring part = &multi[offset];
            if (!joined.empty()) {
                joined += L"; ";
            }
            joined += part;
            offset += part.size() + 1;
        }
        valueOut = joined;
        return true;
    }

    valueOut = L"Type=" + std::to_wstring(type) + L", Bytes=" + std::to_wstring(bytes);
    return true;
}

// addRegistryRow appends one read-only registry evidence row. Inputs are HKLM
// path/value labels; processing never writes or creates keys; no value is returned.
void addRegistryRow(
    std::vector<MiscAuditRow>& rows,
    const std::wstring& category,
    const std::wstring& item,
    const std::wstring& subKey,
    const std::wstring& valueName) {
    std::wstring value;
    std::wstring error;
    if (queryRegistryValueString(subKey, valueName, value, error)) {
        appendRow(rows, category, item, L"已查询", L"Registry HKLM", L"Info", value);
    } else {
        appendRow(rows, category, item, L"Unavailable", L"Registry HKLM", L"Unknown", error);
    }
}

// queryServiceStatusText reads one service/driver status with the Service Control
// Manager using query access only. Inputs are a service name; output is true with
// status text or false with a failure reason.
bool queryServiceStatusText(const std::wstring& serviceName, std::wstring& statusOut, std::wstring& errorOut) {
    SC_HANDLE scm = ::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) {
        errorOut = L"OpenSCManagerW failed: " + getLastErrorText(::GetLastError());
        return false;
    }
    SC_HANDLE service = ::OpenServiceW(scm, serviceName.c_str(), SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG);
    if (!service) {
        const DWORD kError = ::GetLastError();
        ::CloseServiceHandle(scm);
        errorOut = L"OpenServiceW failed: " + getLastErrorText(kError);
        return false;
    }

    SERVICE_STATUS_PROCESS status{};
    DWORD needed = 0;
    if (!::QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&status), sizeof(status), &needed)) {
        const DWORD kError = ::GetLastError();
        ::CloseServiceHandle(service);
        ::CloseServiceHandle(scm);
        errorOut = L"QueryServiceStatusEx failed: " + getLastErrorText(kError);
        return false;
    }

    const wchar_t* stateText = L"Unknown";
    switch (status.dwCurrentState) {
    case SERVICE_STOPPED: stateText = L"Stopped"; break;
    case SERVICE_START_PENDING: stateText = L"StartPending"; break;
    case SERVICE_STOP_PENDING: stateText = L"StopPending"; break;
    case SERVICE_RUNNING: stateText = L"Running"; break;
    case SERVICE_CONTINUE_PENDING: stateText = L"ContinuePending"; break;
    case SERVICE_PAUSE_PENDING: stateText = L"PausePending"; break;
    case SERVICE_PAUSED: stateText = L"Paused"; break;
    default: break;
    }
    statusOut = stateText;
    statusOut += L"; Type=0x";
    std::wostringstream stream;
    stream << std::hex << std::uppercase << status.dwServiceType;
    statusOut += stream.str();
    if (status.dwProcessId != 0) {
        statusOut += L"; PID=" + std::to_wstring(status.dwProcessId);
    }

    ::CloseServiceHandle(service);
    ::CloseServiceHandle(scm);
    return true;
}

// addServiceRow appends one SCM status row. Inputs are a display category/item
// and SCM service name; processing uses query-only SCM handles; no return value.
void addServiceRow(
    std::vector<MiscAuditRow>& rows,
    const std::wstring& category,
    const std::wstring& item,
    const std::wstring& serviceName) {
    std::wstring status;
    std::wstring error;
    if (queryServiceStatusText(serviceName, status, error)) {
        const bool kRunning = status.find(L"Running") != std::wstring::npos;
        appendRow(rows, category, item, kRunning ? L"Present" : L"Not running", L"SCM query", kRunning ? L"Info" : L"Unknown", serviceName + L": " + status);
    } else {
        appendRow(rows, category, item, L"Unavailable", L"SCM query", L"Unknown", serviceName + L": " + error);
    }
}

// addDriverCapabilityRow queries existing ArkDriverClient capability status as
// the only R0-facing check in this module. Inputs are a row list and scope label;
// processing calls the existing wrapper and never opens DeviceIoControl directly;
// no value is returned.
void addDriverCapabilityRow(std::vector<MiscAuditRow>& rows, const std::wstring& scope) {
    const ksword::ark::DriverClient kClient;
    const ksword::ark::DriverCapabilitiesQueryResult kCapability = kClient.queryDriverCapabilities();
    if (kCapability.io.ok) {
        std::wostringstream detail;
        detail << L"Protocol=" << kCapability.driverProtocolVersion
               << L"; StatusFlags=0x" << std::hex << std::uppercase << kCapability.statusFlags
               << L"; DynData=0x" << kCapability.dynDataStatusFlags
               << L"; Returned=" << std::dec << kCapability.returnedFeatureCount << L"/" << kCapability.totalFeatureCount;
        appendRow(rows, scope, L"KswordARK R0 capability", L"Online", L"ArkDriverClient::queryDriverCapabilities", L"Info", detail.str());
    } else {
        std::wstring detail = L"R0 能力查询失败：Win32=" + std::to_wstring(kCapability.io.win32Error) + L"; " +
            std::wstring(kCapability.io.message.begin(), kCapability.io.message.end());
        appendRow(rows, scope, L"KswordARK R0 capability", L"Unavailable", L"ArkDriverClient::queryDriverCapabilities", L"Unknown", detail);
    }
}

// addSecurityAuditRows invokes a new ArkDriverClient security audit wrapper.
// Input: Target rows and page scope.
// Note: Append a read-only summary for Security/DriverTrust/HyperV/AppControl based on the current page.
// Return: No return value; all failure reasons are retained in the details column, avoiding raw DeviceIoControl calls.
void addSecurityAuditRows(std::vector<MiscAuditRow>& rows, const std::wstring& scope) {
    const ksword::ark::DriverClient kClient;
    const auto kSecurity = kClient.querySecurityStatus();
    {
        std::wostringstream detail;
        detail << L"Win32=" << kSecurity.io.win32Error
               << L"; QueryStatus=0x" << std::hex << std::uppercase << static_cast<unsigned long>(kSecurity.response.queryStatus)
               << L"; CIOptions=0x" << kSecurity.response.codeIntegrityOptions
               << L"; SecureBoot=" << std::dec << kSecurity.response.secureBootEnabled
               << L"; VBS=" << kSecurity.response.vbsPresent
               << L"; HVCI=" << kSecurity.response.hvciKmciEnabled
               << L"; TestSigning=" << kSecurity.response.testSigningEnabled;
        appendRow(rows, scope, L"R0 SecurityStatus", kSecurity.io.ok ? L"OK" : (kSecurity.unsupported ? L"Unsupported" : L"Unavailable"), L"ArkDriverClient::querySecurityStatus", kSecurity.io.ok ? L"Info" : L"Unknown", detail.str());
    }

    const auto kTrust = kClient.queryDriverTrustView();
    {
        std::wostringstream detail;
        detail << L"Win32=" << kTrust.io.win32Error
               << L"; total=" << kTrust.totalCount
               << L"; returned=" << kTrust.returnedCount
               << L"; truncated=" << kTrust.truncated
               << L"; moduleStatus=0x" << std::hex << std::uppercase << static_cast<unsigned long>(kTrust.moduleQueryStatus);
        appendRow(rows, scope, L"R0 DriverTrustView", kTrust.io.ok ? L"OK" : (kTrust.unsupported ? L"Unsupported" : L"Unavailable"), L"ArkDriverClient::queryDriverTrustView", kTrust.truncated ? L"Partial" : L"Info", detail.str());
    }

    const auto kHyperv = kClient.queryHyperVSummary();
    {
        std::wostringstream detail;
        detail << L"Win32=" << kHyperv.io.win32Error
               << L"; Hypervisor=" << kHyperv.response.hypervisorPresent
               << L"; VMBus=" << kHyperv.response.vmbusStatus
               << L"; vSwitch=" << kHyperv.response.vSwitchStatus
               << L"; vPCI=" << kHyperv.response.vPciStatus
               << L"; vendor=" << kHyperv.response.hypervisorVendor;
        appendRow(rows, scope, L"R0 HyperVSummary", kHyperv.io.ok ? L"OK" : (kHyperv.unsupported ? L"Unsupported" : L"Unavailable"), L"ArkDriverClient::queryHyperVSummary", kHyperv.io.ok ? L"Info" : L"Unknown", detail.str());
    }

    const auto kAppControl = kClient.queryAppControlStatus();
    {
        std::wostringstream detail;
        detail << L"Win32=" << kAppControl.io.win32Error
               << L"; AppID=" << kAppControl.response.appidStatus
               << L"; AppLockerFilter=" << kAppControl.response.appLockerFilterStatus
               << L"; mssecflt=" << kAppControl.response.mssecfltStatus
               << L"; BAM=" << kAppControl.response.bamStatus
               << L"; owner=" << kAppControl.response.appLockerOwnerModule;
        appendRow(rows, scope, L"R0 AppControlStatus", kAppControl.io.ok ? L"OK" : (kAppControl.unsupported ? L"Unsupported" : L"Unavailable"), L"ArkDriverClient::queryAppControlStatus", kAppControl.io.ok ? L"Info" : L"Unknown", detail.str());
    }
}

// collectCodeIntegrityRows gathers CI/WDAC posture evidence through documented
// R3 queries and registry reads. There is no input; output is a row vector for
// the Code Integrity / WDAC tab.
std::vector<MiscAuditRow> collectCodeIntegrityRows() {
    std::vector<MiscAuditRow> rows;
    addDriverCapabilityRow(rows, L"Code Integrity / WDAC");
    addSecurityAuditRows(rows, L"Code Integrity / WDAC");
    addCommandRow(rows, L"Code Integrity / WDAC", L"SystemCodeIntegrityInformation", L"PowerShell Get-CimInstance Win32_DeviceGuard", runPowerShellScalar(
        L"$dg=Get-CimInstance -Namespace root\\Microsoft\\Windows\\DeviceGuard -ClassName Win32_DeviceGuard -ErrorAction Stop; "
        L"'AvailableSecurityProperties=' + (($dg.AvailableSecurityProperties)-join ',') + '; SecurityServicesConfigured=' + (($dg.SecurityServicesConfigured)-join ',') + '; SecurityServicesRunning=' + (($dg.SecurityServicesRunning)-join ',') + '; CodeIntegrityPolicyEnforcementStatus=' + $dg.CodeIntegrityPolicyEnforcementStatus + '; UsermodeCodeIntegrityPolicyEnforcementStatus=' + $dg.UsermodeCodeIntegrityPolicyEnforcementStatus"));
    addCommandRow(rows, L"Code Integrity / WDAC", L"CI policy files", L"PowerShell Get-ChildItem", runPowerShellScalar(
        L"$paths=@('$env:windir\\System32\\CodeIntegrity\\CiPolicies\\Active','$env:windir\\System32\\CodeIntegrity'); "
        L"foreach($p in $paths){ if(Test-Path $p){ $c=(Get-ChildItem -LiteralPath $p -File -ErrorAction SilentlyContinue | Measure-Object).Count; Write-Output ($p + '=' + $c) } else { Write-Output ($p + '=missing') } }"));
    addRegistryRow(rows, L"Code Integrity / WDAC", L"Policy UpgradedSystem", L"SYSTEM\\CurrentControlSet\\Control\\CI\\Policy", L"UpgradedSystem");
    addRegistryRow(rows, L"Code Integrity / WDAC", L"Code Integrity Enabled", L"SYSTEM\\CurrentControlSet\\Control\\CI\\Config", L"Enabled");
    addRegistryRow(rows, L"Code Integrity / WDAC", L"Secure Boot state cache", L"SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State", L"UEFISecureBootEnabled");
    addServiceRow(rows, L"Code Integrity / WDAC", L"Code Integrity driver", L"CI");
    return rows;
}

// collectVbsRows gathers VBS/HVCI/SKCI evidence from DeviceGuard CIM, systeminfo
// and service/module presence. There is no input; output is a row vector for the
// VBS/HVCI/SKCI tab.
std::vector<MiscAuditRow> collectVbsRows() {
    std::vector<MiscAuditRow> rows;
    addDriverCapabilityRow(rows, L"VBS / HVCI / SKCI");
    addSecurityAuditRows(rows, L"VBS / HVCI / SKCI");
    addCommandRow(rows, L"VBS / HVCI / SKCI", L"DeviceGuard status", L"PowerShell CIM root/Microsoft/Windows/DeviceGuard", runPowerShellScalar(
        L"$dg=Get-CimInstance -Namespace root\\Microsoft\\Windows\\DeviceGuard -ClassName Win32_DeviceGuard -ErrorAction Stop; "
        L"'VirtualizationBasedSecurityStatus=' + $dg.VirtualizationBasedSecurityStatus + '; RequiredSecurityProperties=' + (($dg.RequiredSecurityProperties)-join ',') + '; AvailableSecurityProperties=' + (($dg.AvailableSecurityProperties)-join ',') + '; Running=' + (($dg.SecurityServicesRunning)-join ',') + '; Configured=' + (($dg.SecurityServicesConfigured)-join ',')"));
    addCommandRow(rows, L"VBS / HVCI / SKCI", L"HVCI memory integrity", L"PowerShell registry", runPowerShellScalar(
        L"$p='HKLM:\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity'; "
        L"if(Test-Path $p){ Get-ItemProperty -LiteralPath $p | Select-Object -Property Enabled,WasEnabledBy,Locked | Format-List | Out-String } else { 'HVCI scenario key missing' }"));
    addCommandRow(rows, L"VBS / HVCI / SKCI", L"Secure Kernel modules", L"PowerShell Get-ProcessModule/System32", runPowerShellScalar(
        L"$names=@('securekernel.exe','skci.dll','ci.dll'); foreach($n in $names){ $p=Join-Path $env:windir ('System32\\' + $n); if(Test-Path $p){ Write-Output ($n + '=present') } else { Write-Output ($n + '=missing') } }"));
    addRegistryRow(rows, L"VBS / HVCI / SKCI", L"DeviceGuard EnableVirtualizationBasedSecurity", L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard", L"EnableVirtualizationBasedSecurity");
    addRegistryRow(rows, L"VBS / HVCI / SKCI", L"DeviceGuard RequirePlatformSecurityFeatures", L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard", L"RequirePlatformSecurityFeatures");
    addRegistryRow(rows, L"VBS / HVCI / SKCI", L"LsaCfgFlags", L"SYSTEM\\CurrentControlSet\\Control\\Lsa", L"LsaCfgFlags");
    return rows;
}

// collectHyperVRows gathers Hyper-V, VMBus, vSwitch, vPCI and HvSocket posture
// with read-only service/module/CIM evidence. There is no input; output is a row
// vector for the Hyper-V tab.
std::vector<MiscAuditRow> collectHyperVRows() {
    std::vector<MiscAuditRow> rows;
    addDriverCapabilityRow(rows, L"Hyper-V / VMBus / HvSocket");
    addSecurityAuditRows(rows, L"Hyper-V / VMBus / HvSocket");
    addCommandRow(rows, L"Hyper-V / VMBus / HvSocket", L"ComputerSystem hypervisor", L"PowerShell CIM Win32_ComputerSystem", runPowerShellScalar(
        L"$cs=Get-CimInstance Win32_ComputerSystem -ErrorAction Stop; 'HypervisorPresent=' + $cs.HypervisorPresent + '; Manufacturer=' + $cs.Manufacturer + '; Model=' + $cs.Model"));
    addCommandRow(rows, L"Hyper-V / VMBus / HvSocket", L"Hyper-V optional features", L"PowerShell Get-WindowsOptionalFeature", runPowerShellScalar(
        L"$names=@('Microsoft-Hyper-V-All','Microsoft-Hyper-V-Hypervisor','VirtualMachinePlatform','Microsoft-Windows-Subsystem-Linux'); foreach($n in $names){ $f=Get-WindowsOptionalFeature -Online -FeatureName $n -ErrorAction SilentlyContinue; if($f){ Write-Output ($n + '=' + $f.State) } else { Write-Output ($n + '=Unavailable') } }"));
    addCommandRow(rows, L"Hyper-V / VMBus / HvSocket", L"Hyper-V network adapters", L"PowerShell CIM Win32_PnPEntity", runPowerShellScalar(
        L"Get-CimInstance Win32_PnPEntity -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'Hyper-V|VMBus|vmbus|Virtual Switch|vEthernet|HvSocket' } | Select-Object -First 40 -Property Name,PNPClass,Status | Format-Table -AutoSize | Out-String"));
    addServiceRow(rows, L"Hyper-V / VMBus / HvSocket", L"VMBus kernel driver", L"vmbus");
    addServiceRow(rows, L"Hyper-V / VMBus / HvSocket", L"Hyper-V Virtual Switch Extension Adapter", L"VMSMP");
    addServiceRow(rows, L"Hyper-V / VMBus / HvSocket", L"Hyper-V socket service", L"HvHost");
    addServiceRow(rows, L"Hyper-V / VMBus / HvSocket", L"Virtual PCI bus", L"vpci");
    addRegistryRow(rows, L"Hyper-V / VMBus / HvSocket", L"Hypervisor launch type", L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard", L"HypervisorEnforcedCodeIntegrity");
    return rows;
}

// collectAppLockerRows gathers AppID/AppLocker/appid.sys/applockerfltr/mssecflt
// evidence without policy mutation or rule export. There is no input; output is
// a row vector for the AppLocker tab.
std::vector<MiscAuditRow> collectAppLockerRows() {
    std::vector<MiscAuditRow> rows;
    addDriverCapabilityRow(rows, L"AppLocker / AppID");
    addSecurityAuditRows(rows, L"AppLocker / AppID");
    addCommandRow(rows, L"AppLocker / AppID", L"Effective AppLocker policy count", L"PowerShell Get-AppLockerPolicy", runPowerShellScalar(
        L"try { $p=Get-AppLockerPolicy -Effective -ErrorAction Stop; $xml=[xml]($p.ToXml()); $rules=($xml.AppLockerPolicy.RuleCollection | ForEach-Object { $_.ChildNodes.Count } | Measure-Object -Sum).Sum; 'RuleCollections=' + $xml.AppLockerPolicy.RuleCollection.Count + '; RuleCount=' + $rules } catch { 'Get-AppLockerPolicy failed: ' + $_.Exception.Message; exit 1 }"));
    addCommandRow(rows, L"AppLocker / AppID", L"AppID service", L"PowerShell Get-Service", runPowerShellScalar(
        L"Get-Service -Name AppIDSvc -ErrorAction Stop | Select-Object Name,Status,StartType | Format-List | Out-String"));
    addCommandRow(rows, L"AppLocker / AppID", L"Application Control event logs", L"PowerShell Get-WinEvent", runPowerShellScalar(
        L"$logs=@('Microsoft-Windows-AppLocker/EXE and DLL','Microsoft-Windows-AppLocker/MSI and Script','Microsoft-Windows-CodeIntegrity/Operational'); foreach($l in $logs){ $log=Get-WinEvent -ListLog $l -ErrorAction SilentlyContinue; if($log){ Write-Output ($l + '=enabled:' + $log.IsEnabled + '; records:' + $log.RecordCount) } else { Write-Output ($l + '=Unavailable') } }"));
    addServiceRow(rows, L"AppLocker / AppID", L"AppID kernel driver", L"AppID");
    addServiceRow(rows, L"AppLocker / AppID", L"AppLocker minifilter", L"applockerfltr");
    addServiceRow(rows, L"AppLocker / AppID", L"Microsoft security filter", L"mssecflt");
    addRegistryRow(rows, L"AppLocker / AppID", L"SRP identifiers policy", L"SOFTWARE\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers", L"DefaultLevel");
    return rows;
}

// collectAuxiliaryRows gathers BAM and ahcache availability in privacy-preserving
// summary mode. There is no input; output is a row vector for the BAM/ahcache tab.
std::vector<MiscAuditRow> collectAuxiliaryRows() {
    std::vector<MiscAuditRow> rows;
    addDriverCapabilityRow(rows, L"BAM / ahcache");
    addSecurityAuditRows(rows, L"BAM / ahcache");
    addCommandRow(rows, L"BAM / ahcache", L"BAM registry summary", L"PowerShell registry count", runPowerShellScalar(
        L"$p='HKLM:\\SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings'; if(Test-Path $p){ $users=(Get-ChildItem -LiteralPath $p -ErrorAction SilentlyContinue | Measure-Object).Count; 'UserSettingsKeys=' + $users + '; privacyMode=SummaryOnly' } else { 'BAM UserSettings key missing' }"));
    addCommandRow(rows, L"BAM / ahcache", L"Amcache availability", L"PowerShell file summary", runPowerShellScalar(
        L"$p=Join-Path $env:windir 'AppCompat\\Programs\\Amcache.hve'; if(Test-Path $p){ $i=Get-Item -LiteralPath $p; 'AmcachePresent=true; Length=' + $i.Length + '; LastWriteUtc=' + $i.LastWriteTimeUtc.ToString('o') + '; privacyMode=SummaryOnly' } else { 'Amcache.hve missing' }"));
    addCommandRow(rows, L"BAM / ahcache", L"AppCompat cache service keys", L"PowerShell registry summary", runPowerShellScalar(
        L"$keys=@('HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache','HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags'); foreach($k in $keys){ if(Test-Path $k){ Write-Output ($k + '=present') } else { Write-Output ($k + '=missing') } }"));
    addServiceRow(rows, L"BAM / ahcache", L"BAM driver", L"bam");
    addServiceRow(rows, L"BAM / ahcache", L"Application Compatibility Cache", L"ahcache");
    appendRow(rows, L"BAM / ahcache", L"Privacy boundary", L"SummaryOnly", L"UI policy", L"Info", L"默认只显示状态、计数和可用性，不枚举用户执行历史明细、不导出路径时间线。");
    return rows;
}

// collectBugcheckRows reports only feature applicability. The R0 feature is
// VMware-only and its valid upload path is intentionally quiet when inactive,
// so this page never claims that a successful transport activated a panel.
std::vector<MiscAuditRow> collectBugcheckRows() {
    std::vector<MiscAuditRow> rows;
    addDriverCapabilityRow(rows, L"Bugcheck / VMware branding");
    addCommandRow(rows, L"Bugcheck / VMware branding", L"VMware environment", L"PowerShell Win32_ComputerSystem", runPowerShellScalar(
        L"$c=Get-CimInstance Win32_ComputerSystem -ErrorAction Stop; 'Manufacturer=' + $c.Manufacturer + '; Model=' + $c.Model"));
    appendRow(rows, L"Bugcheck / VMware branding", L"R0 feature scope", L"VMware-only", L"KswordARK bugcheck runtime", L"Info",
        L"驱动仅在检测到受支持的 VMware 显示环境时启用该诊断面板；非 VMware 环境会安全忽略合法上传包。");
    appendRow(rows, L"Bugcheck / VMware branding", L"内置测试位图", L"Explicit action required", L"ArkDriverClient::setBugcheckBitmap", L"Low",
        L"点击“上传内置位图”后才会在后台发送 16×16 BGRA 测试图；不会自动上传，也不会改变 Bugcheck 策略。传输成功不代表 VMware 面板已经激活。");
    return rows;
}

// collectRowsForPage dispatches a tab id to its read-only collector. Input is a
// stable page id; processing performs local R3 queries; output is the fresh row
// snapshot used by refreshAuditView.
std::vector<MiscAuditRow> collectRowsForPage(const MiscAuditPageId pageId) {
    switch (pageId) {
    case MiscAuditPageId::kCodeIntegrity:
        return collectCodeIntegrityRows();
    case MiscAuditPageId::kVbsHvciSkci:
        return collectVbsRows();
    case MiscAuditPageId::kHyperV:
        return collectHyperVRows();
    case MiscAuditPageId::kAppLocker:
        return collectAppLockerRows();
    case MiscAuditPageId::kBamAhcache:
        return collectAuxiliaryRows();
    case MiscAuditPageId::kBugcheck:
        return collectBugcheckRows();
    default:
        return {};
    }
}

// auditColumns returns the fixed ListView schema shared by every Misc tab. There
// is no input; output is consumed by addListViewColumns during page creation.
std::vector<ksword::ui::ListViewColumn> auditColumns() {
    return {
        { 0, 190, LVCFMT_LEFT, L"类别" },
        { 1, 250, LVCFMT_LEFT, L"项目" },
        { 2, 130, LVCFMT_LEFT, L"状态" },
        { 3, 260, LVCFMT_LEFT, L"来源" },
        { 4, 100, LVCFMT_LEFT, L"风险" },
        { 5, 620, LVCFMT_LEFT, L"详情 / 失败原因" },
    };
}

std::vector<std::wstring> auditCells(const MiscAuditRow& row) {
    return { row.category, row.item, row.state, row.source, row.risk, row.detail };
}

std::wstring auditStableKey(const MiscAuditRow& row) {
    return row.category + L"\n" + row.item + L"\n" + row.source;
}

std::vector<ksword::ui::VirtualListRow> buildAuditVirtualRows(const std::vector<MiscAuditRow>& rows) {
    std::vector<ksword::ui::VirtualListRow> displayRows;
    displayRows.reserve(rows.size());
    for (std::size_t index = 0; index < rows.size(); ++index) {
        ksword::ui::VirtualListRow display{};
        display.stableKey = auditStableKey(rows[index]);
        display.cells = auditCells(rows[index]);
        display.itemData = static_cast<LPARAM>(index);
        displayRows.push_back(std::move(display));
    }
    return displayRows;
}

std::wstring stableKeyAt(const MiscAuditViewState& state, const int visibleIndex) {
    if (visibleIndex < 0 || visibleIndex >= static_cast<int>(state.visibleRows.size())) {
        return {};
    }
    return auditStableKey(state.visibleRows[static_cast<std::size_t>(visibleIndex)]);
}

void restoreListPosition(MiscAuditViewState& state, const std::wstring& selectedKey, const std::wstring& topKey) {
    int selectedIndex = -1;
    int topIndex = -1;
    for (std::size_t index = 0; index < state.visibleRows.size(); ++index) {
        const std::wstring kKey = auditStableKey(state.visibleRows[index]);
        if (!selectedKey.empty() && kKey == selectedKey) {
            selectedIndex = static_cast<int>(index);
        }
        if (!topKey.empty() && kKey == topKey) {
            topIndex = static_cast<int>(index);
        }
    }
    if (selectedIndex >= 0) {
        ListView_SetItemState(state.list, selectedIndex, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
    }
    if (topIndex >= 0) {
        ListView_EnsureVisible(state.list, topIndex, FALSE);
    }
}

// requestAuditFilter runs local matching against the immutable text snapshot.
// Registry, service, WMI and R0 probes are never repeated while typing.
void requestAuditFilter(MiscAuditViewState& state, std::wstring query) {
    if (!state.filterTask || !state.filterRows) {
        return;
    }
    state.filterQuery = std::move(query);
    state.filterUseRegex = ksword::ui::getFilterBarRegexEnabled(state.filterBar);
    const std::uint64_t kGeneration = state.snapshotGeneration;
    const auto kRows = state.filterRows;
    const bool kUseRegex = state.filterUseRegex;
    state.filterTask->request(
        [kRows, kGeneration, kUseRegex, query = state.filterQuery]() mutable {
            MiscAuditFilterResult result{};
            result.generation = kGeneration;
            result.query = std::move(query);
            result.useRegex = kUseRegex;
            result.visibleIndexes = ksword::ui::VirtualListView::filterRowIndexes(*kRows, result.query, kUseRegex);
            return result;
        },
        [&state](std::uint64_t, std::optional<MiscAuditFilterResult>&& result, std::exception_ptr error) {
            if (error || !result.has_value() || result->generation != state.snapshotGeneration ||
                result->query != state.filterQuery || result->useRegex != state.filterUseRegex) {
                return;
            }
            const std::wstring kSelectedKey = stableKeyAt(state, ListView_GetNextItem(state.list, -1, LVNI_SELECTED));
            const std::wstring kTopKey = stableKeyAt(state, ListView_GetTopIndex(state.list));
            state.visibleRows.clear();
            state.visibleRows.reserve(result->visibleIndexes.size());
            for (const std::size_t kIndex : result->visibleIndexes) {
                if (kIndex < state.rows.size()) {
                    state.visibleRows.push_back(state.rows[kIndex]);
                }
            }
            state.virtualList.setVisibleIndexes(std::move(result->visibleIndexes));
            restoreListPosition(state, kSelectedKey, kTopKey);
        });
}

// populateAuditList installs a new immutable owner-data snapshot after its
// collector finishes. The old result remains interactive until this point.
void populateAuditList(MiscAuditViewState& state) {
    if (!state.list) {
        return;
    }
    state.filterRows = std::make_shared<const std::vector<ksword::ui::VirtualListRow>>(buildAuditVirtualRows(state.rows));
    ++state.snapshotGeneration;
    state.virtualList.setRows(*state.filterRows);
    requestAuditFilter(state, state.filterBar ? ksword::ui::getFilterBarText(state.filterBar) : state.filterQuery);
}

// buildRowsTsv converts current rows to clipboard-friendly TSV. Input is a row
// vector; processing does not escape beyond replacing line breaks; output is text
// suitable for copy/paste into a spreadsheet.
std::wstring buildRowsTsv(const std::vector<MiscAuditRow>& rows) {
    auto clean = [](std::wstring text) {
        std::replace(text.begin(), text.end(), L'\r', L' ');
        std::replace(text.begin(), text.end(), L'\n', L' ');
        std::replace(text.begin(), text.end(), L'\t', L' ');
        return text;
    };

    std::wostringstream stream;
    stream << L"类别\t项目\t状态\t来源\t风险\t详情\r\n";
    for (const MiscAuditRow& row : rows) {
        stream << clean(row.category) << L'\t'
               << clean(row.item) << L'\t'
               << clean(row.state) << L'\t'
               << clean(row.source) << L'\t'
               << clean(row.risk) << L'\t'
               << clean(row.detail) << L"\r\n";
    }
    return stream.str();
}

// writeClipboardText copies Unicode text to the clipboard. Inputs are owner HWND
// and text; processing transfers a movable global allocation to Windows; output
// reports success for status messages.
bool writeClipboardText(HWND owner, const std::wstring& text) {
    if (text.empty() || !::OpenClipboard(owner)) {
        return false;
    }
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
    ::EmptyClipboard();
    if (!::SetClipboardData(CF_UNICODETEXT, memory)) {
        ::GlobalFree(memory);
        ::CloseClipboard();
        return false;
    }
    ::CloseClipboard();
    return true;
}

// selectedRowIndex returns the selected ListView row index. Input is a page state;
// output is -1 when no row is selected.
int selectedRowIndex(const MiscAuditViewState& state) {
    return state.list ? ListView_GetNextItem(state.list, -1, LVNI_SELECTED) : -1;
}

// copySelectedRow copies one evidence row as TSV. Input is a page state; process
// reads only the current in-memory row; no return value is produced.
void copySelectedRow(MiscAuditViewState& state) {
    const int kIndex = selectedRowIndex(state);
    if (kIndex < 0 || kIndex >= static_cast<int>(state.visibleRows.size())) {
        state.statusText = L"没有选中可复制的行。";
        ::InvalidateRect(state.hwnd, nullptr, TRUE);
        return;
    }
    const bool kOk = writeClipboardText(state.hwnd, buildRowsTsv({ state.visibleRows[static_cast<std::size_t>(kIndex)] }));
    state.statusText = kOk ? L"已复制当前行。" : L"复制当前行失败。";
    ::InvalidateRect(state.hwnd, nullptr, TRUE);
}

// copyAllRows copies the currently visible local result as TSV. It does not
// trigger an audit refresh and therefore remains instantaneous while typing.
void copyAllRows(MiscAuditViewState& state) {
    const bool kOk = writeClipboardText(state.hwnd, buildRowsTsv(state.visibleRows));
    state.statusText = kOk ? L"已复制可见审计结果。" : L"复制可见审计结果失败。";
    ::InvalidateRect(state.hwnd, nullptr, TRUE);
}

// refreshAuditView schedules all command, registry, service and R0 work in a
// snapshot worker. Repeated clicks coalesce and the old table stays available.
void refreshAuditView(MiscAuditViewState& state) {
    if (!state.refreshTask) {
        return;
    }
    state.statusText = state.refreshTask->running()
        ? L"审计刷新已排队，等待当前快照完成…"
        : L"正在后台刷新只读审计证据…";
    ::EnableWindow(state.refreshButton, FALSE);
    if (state.rows.empty()) {
        ksword::ui::setLoadingOverlay(state.loadingOverlay, true, L"正在加载安全审计快照…");
    }
    ::InvalidateRect(state.hwnd, nullptr, TRUE);
    const MiscAuditPageId kPageId = state.pageId;
    state.refreshTask->request(
        [kPageId] {
            MiscAuditRefreshResult result{};
            result.pageId = kPageId;
            result.rows = collectRowsForPage(kPageId);
            return result;
        },
        [&state](std::uint64_t, std::optional<MiscAuditRefreshResult>&& result, std::exception_ptr error) {
            ::EnableWindow(state.refreshButton, TRUE);
            ksword::ui::setLoadingOverlay(state.loadingOverlay, false);
            if (error || !result.has_value() || result->pageId != state.pageId) {
                state.statusText = L"安全审计后台刷新异常结束，已保留旧结果。";
                ::InvalidateRect(state.hwnd, nullptr, TRUE);
                return;
            }
            state.rows = std::move(result->rows);
            populateAuditList(state);
            std::size_t unavailable = 0;
            for (const MiscAuditRow& row : state.rows) {
                if (row.state == L"Unavailable" || row.state == L"Unsupported") {
                    ++unavailable;
                }
            }
            state.statusText = L"Rows=" + std::to_wstring(state.rows.size()) +
                L"; Unavailable=" + std::to_wstring(unavailable) +
                L"; 默认只读审计，失败原因保留在详情列。";
            ::InvalidateRect(state.hwnd, nullptr, TRUE);
        });
}

// uploadBuiltinBugcheckBitmap sends a fixed, bounded 16x16 BGRA diagnostic tile
// only after explicit UI confirmation. The work and IOCTL both run in the page's
// background task; the active audit snapshot remains usable while it runs.
void uploadBuiltinBugcheckBitmap(MiscAuditViewState& state) {
    if (state.pageId != MiscAuditPageId::kBugcheck || !state.bugcheckUploadTask) {
        return;
    }
    if (state.bugcheckUploadTask->running()) {
        state.statusText = L"Bugcheck 位图上传已在后台执行。";
        ::InvalidateRect(state.hwnd, nullptr, TRUE);
        return;
    }
    const int kAnswer = ::MessageBoxW(state.hwnd,
        L"将上传内置的 16×16 BGRA 诊断位图到 KswordARK。\n\n"
        L"该操作只影响受支持 VMware 环境中的驱动缓存。驱动会在非支持环境安全忽略合法数据包，"
        L"不会修改系统 Bugcheck 策略或主动触发蓝屏。是否继续？",
        L"确认上传 Bugcheck 诊断位图", MB_YESNO | MB_DEFBUTTON2 | MB_ICONWARNING);
    if (kAnswer != IDYES) {
        state.statusText = L"已取消 Bugcheck 位图上传。";
        ::InvalidateRect(state.hwnd, nullptr, TRUE);
        return;
    }
    ::EnableWindow(state.bugcheckUploadButton, FALSE);
    state.statusText = L"正在后台上传 Bugcheck 内置诊断位图…";
    ::InvalidateRect(state.hwnd, nullptr, TRUE);
    state.bugcheckUploadTask->request(
        [] {
            constexpr std::uint32_t kWidth = 16;
            constexpr std::uint32_t kHeight = 16;
            constexpr std::uint32_t kStride = kWidth * 4;
            std::vector<std::uint8_t> pixels(static_cast<std::size_t>(kStride) * kHeight, 0);
            for (std::uint32_t y = 0; y < kHeight; ++y) {
                for (std::uint32_t x = 0; x < kWidth; ++x) {
                    const std::size_t kOffset = (static_cast<std::size_t>(y) * kStride) + (static_cast<std::size_t>(x) * 4U);
                    const bool kAccent = ((x / 4U) + (y / 4U)) % 2U == 0U;
                    pixels[kOffset] = kAccent ? 0xD7U : 0x9BU;
                    pixels[kOffset + 1U] = kAccent ? 0x83U : 0x56U;
                    pixels[kOffset + 2U] = kAccent ? 0x21U : 0x1BU;
                    pixels[kOffset + 3U] = 0xFFU;
                }
            }
            BugcheckUploadResult result{};
            result.io = ksword::ark::DriverClient().setBugcheckBitmap(kWidth, kHeight, kStride, 0x2183D7U, pixels);
            return result;
        },
        [&state](std::uint64_t, std::optional<BugcheckUploadResult>&& result, std::exception_ptr error) {
            ::EnableWindow(state.bugcheckUploadButton, TRUE);
            if (error || !result.has_value()) {
                state.statusText = L"Bugcheck 位图后台上传异常结束。";
                ::InvalidateRect(state.hwnd, nullptr, TRUE);
                return;
            }
            const ksword::ark::IoResult& io = result->io;
            appendRow(state.rows, L"Bugcheck / VMware branding", L"内置测试位图上传",
                io.ok ? L"Transport OK" : L"Transport failed",
                L"ArkDriverClient::setBugcheckBitmap", io.ok ? L"Info" : L"Unknown",
                L"16x16 BGRA; brandColor=#2183D7; Win32=" + std::to_wstring(io.win32Error) +
                L"; bytes=" + std::to_wstring(io.bytesReturned) + L"; " + std::wstring(io.message.begin(), io.message.end()));
            populateAuditList(state);
            state.statusText = io.ok
                ? L"Bugcheck 位图传输完成。请注意：非 VMware 环境会被驱动安全忽略。"
                : L"Bugcheck 位图传输失败，详细原因已加入结果列表。";
            ::InvalidateRect(state.hwnd, nullptr, TRUE);
        });
}

void ensureAuditViewLoaded(HWND view) {
    MiscAuditViewState* state = stateFromAuditView(view);
    if (state && !state->hasLoaded) {
        state->hasLoaded = true;
        refreshAuditView(*state);
    }
}

// layoutAuditView places toolbar and ListView inside one Misc tab. Input is page
// state; processing uses current client size; no value is returned.
void layoutAuditView(MiscAuditViewState& state) {
    if (!state.hwnd) {
        return;
    }
    RECT rc{};
    ::GetClientRect(state.hwnd, &rc);
    const int kWidth = width(rc);
    const int kHeight = height(rc);
    ::MoveWindow(state.refreshButton, kGap, kGap, 86, 24, TRUE);
    ::MoveWindow(state.copyButton, kGap + 94, kGap, 106, 24, TRUE);
    const bool kBugcheckPage = state.pageId == MiscAuditPageId::kBugcheck;
    ::ShowWindow(state.bugcheckUploadButton, kBugcheckPage ? SW_SHOW : SW_HIDE);
    ::MoveWindow(state.bugcheckUploadButton, kGap + 208, kGap, 126, 24, TRUE);
    ::MoveWindow(state.filterBar, kGap, 34, std::max(100, kWidth - (kGap * 2)), 28, TRUE);
    const int kTop = kHeaderHeight + kGap;
    ::MoveWindow(state.list, kGap, kTop, std::max(0, kWidth - (kGap * 2)), std::max(0, kHeight - kTop - kGap), TRUE);
    ::MoveWindow(state.loadingOverlay, kGap, kTop, std::max(0, kWidth - (kGap * 2)), std::max(0, kHeight - kTop - kGap), TRUE);
}

// showAuditContextMenu displays only read-only actions. Inputs are page state and
// a screen point; processing can refresh or copy rows; no mutation command exists.
void showAuditContextMenu(MiscAuditViewState& state, POINT screenPoint) {
    if (!state.list) {
        return;
    }
    POINT clientPoint = screenPoint;
    ::ScreenToClient(state.list, &clientPoint);
    LVHITTESTINFO hit{};
    hit.pt = clientPoint;
    const int kItem = ListView_HitTest(state.list, &hit);
    state.contextColumn = std::max(0, hit.iSubItem);
    if (kItem >= 0) {
        ListView_SetItemState(state.list, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
        ListView_SetItemState(state.list, kItem, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
    }

    HMENU menu = ::CreatePopupMenu();
    if (!menu) {
        return;
    }
    const bool kHasSelection = selectedRowIndex(state) >= 0;
    ::AppendMenuW(menu, MF_STRING, kMenuRefresh, L"刷新只读审计");
    ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    ::AppendMenuW(menu, MF_STRING | (kHasSelection ? 0U : MF_GRAYED), kMenuCopyRow, L"复制当前行");
    ::AppendMenuW(menu, MF_STRING | (kHasSelection ? 0U : MF_GRAYED), kMenuCopyCell, L"复制单元格");
    ::AppendMenuW(menu, MF_STRING, kMenuCopyAll, L"复制可见结果");

    const UINT kCommand = ::TrackPopupMenu(menu, TPM_RETURNCMD | TPM_RIGHTBUTTON, screenPoint.x, screenPoint.y, 0, state.hwnd, nullptr);
    ::DestroyMenu(menu);
    switch (kCommand) {
    case kMenuRefresh:
        refreshAuditView(state);
        break;
    case kMenuCopyRow:
        copySelectedRow(state);
        break;
    case kMenuCopyCell: {
        const int kSelected = selectedRowIndex(state);
        if (kSelected >= 0 && kSelected < static_cast<int>(state.visibleRows.size())) {
            const std::vector<std::wstring> kCells = auditCells(state.visibleRows[static_cast<std::size_t>(kSelected)]);
            const std::size_t kColumn = static_cast<std::size_t>(std::max(0, state.contextColumn));
            const bool kOk = writeClipboardText(state.hwnd, kColumn < kCells.size() ? kCells[kColumn] : std::wstring{});
            state.statusText = kOk ? L"已复制单元格。" : L"复制单元格失败。";
            ::InvalidateRect(state.hwnd, nullptr, TRUE);
        }
        break;
    }
    case kMenuCopyAll:
        copyAllRows(state);
        break;
    default:
        break;
    }
}

// createAuditChildControls creates one tab page's toolbar and report ListView.
// Input is the page state and HWND; processing adds fixed columns; output is true
// when all controls exist.
bool createAuditChildControls(MiscAuditViewState& state, HWND hwnd) {
    state.refreshButton = ksword::ui::createButton(hwnd, kRefreshButtonId, L"Refresh", 0, 0, 80, 24);
    state.copyButton = ksword::ui::createButton(hwnd, kCopyButtonId, L"Copy TSV", 0, 0, 100, 24);
    state.bugcheckUploadButton = ksword::ui::createButton(hwnd, kBugcheckUploadButtonId, L"上传内置位图", 0, 0, 120, 24);
    state.filterBar = ksword::ui::createFilterBar(hwnd, kFilterBarId,
        L"筛选类别、项目、状态、来源、风险和详情", 0, 0, 0, 0);
    if (!state.refreshButton || !state.copyButton || !state.bugcheckUploadButton || !state.filterBar ||
        !state.virtualList.create(hwnd, kListId, 0, 0, 0, 0, LVS_SHOWSELALWAYS | LVS_SINGLESEL)) {
        return false;
    }
    state.list = state.virtualList.hwnd();
    state.virtualList.addColumns(auditColumns());
    state.loadingOverlay = ksword::ui::createLoadingOverlay(hwnd, kLoadingOverlayId, { 0, 0, 1, 1 });
    state.refreshTask = std::make_unique<ksword::ui::AsyncSnapshotTask<MiscAuditRefreshResult>>(hwnd, kMsgAuditRefreshCompleted);
    state.filterTask = std::make_unique<ksword::ui::AsyncSnapshotTask<MiscAuditFilterResult>>(hwnd, kMsgAuditFilterCompleted);
    state.bugcheckUploadTask = std::make_unique<ksword::ui::AsyncSnapshotTask<BugcheckUploadResult>>(hwnd, kMsgBugcheckUploadCompleted);
    if (!state.loadingOverlay || !state.refreshTask || !state.filterTask || !state.bugcheckUploadTask) {
        return false;
    }
    ksword::ui::setWindowFontRecursive(hwnd);
    return true;
}

// registerAuditViewClass registers the retained child page class once. There is
// no input; output is true when CreateWindowExW can instantiate the class.
bool registerAuditViewClass() {
    static bool registered = false;
    if (registered) {
        return true;
    }

    WNDCLASSW wc{};
    wc.lpfnWndProc = [](HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) -> LRESULT {
        MiscAuditViewState* state = stateFromAuditView(hwnd);
        if (msg == WM_NCCREATE) {
            auto* create = reinterpret_cast<CREATESTRUCTW*>(lParam);
            state = create ? static_cast<MiscAuditViewState*>(create->lpCreateParams) : nullptr;
            if (state) {
                state->hwnd = hwnd;
                ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(state));
            }
        }

        switch (msg) {
        case WM_CREATE:
            if (state) {
                if (!createAuditChildControls(*state, hwnd)) {
                    delete state;
                    ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
                    return -1;
                }
                layoutAuditView(*state);
            }
            return 0;
        case WM_SIZE:
            if (state) {
                layoutAuditView(*state);
            }
            return 0;
        case WM_COMMAND:
            if (state && LOWORD(wParam) == kRefreshButtonId) {
                refreshAuditView(*state);
                return 0;
            }
            if (state && LOWORD(wParam) == kCopyButtonId) {
                copyAllRows(*state);
                return 0;
            }
            if (state && LOWORD(wParam) == kBugcheckUploadButtonId) {
                uploadBuiltinBugcheckBitmap(*state);
                return 0;
            }
            if (state && LOWORD(wParam) == kFilterBarId && HIWORD(wParam) == EN_CHANGE) {
                requestAuditFilter(*state, ksword::ui::getFilterBarText(state->filterBar));
                return 0;
            }
            break;
        case kMsgAuditRefreshCompleted:
            if (state && state->refreshTask && state->refreshTask->consume(hwnd, wParam, lParam)) {
                return 0;
            }
            break;
        case kMsgAuditFilterCompleted:
            if (state && state->filterTask && state->filterTask->consume(hwnd, wParam, lParam)) {
                return 0;
            }
            break;
        case kMsgBugcheckUploadCompleted:
            if (state && state->bugcheckUploadTask && state->bugcheckUploadTask->consume(hwnd, wParam, lParam)) {
                return 0;
            }
            break;
        case WM_NOTIFY:
            if (state) {
                const auto* header = reinterpret_cast<const NMHDR*>(lParam);
                LRESULT virtualResult = 0;
                if (header && state->virtualList.handleNotify(*header, virtualResult)) {
                    return virtualResult;
                }
                if (header && header->hwndFrom == state->list && header->code == NM_RCLICK) {
                    POINT pt{};
                    ::GetCursorPos(&pt);
                    showAuditContextMenu(*state, pt);
                    return 0;
                }
            }
            break;
        case WM_CONTEXTMENU:
            if (state && reinterpret_cast<HWND>(wParam) == state->list) {
                POINT pt{ GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam) };
                if (pt.x == -1 && pt.y == -1) {
                    RECT rc{};
                    ::GetWindowRect(state->list, &rc);
                    pt = { rc.left + 24, rc.top + 24 };
                }
                showAuditContextMenu(*state, pt);
                return 0;
            }
            break;
        case WM_CTLCOLORSTATIC: {
            HDC dc = reinterpret_cast<HDC>(wParam);
            ::SetBkMode(dc, TRANSPARENT);
            ::SetTextColor(dc, ksword::ui::appTheme().textColor);
            return reinterpret_cast<LRESULT>(ksword::ui::appTheme().panelBrush());
        }
        case WM_PAINT: {
            PAINTSTRUCT ps{};
            HDC dc = ::BeginPaint(hwnd, &ps);
            RECT rc{};
            ::GetClientRect(hwnd, &rc);
            ::FillRect(dc, &rc, ksword::ui::appTheme().panelBrush());
            const int kTextLeft = state && state->pageId == MiscAuditPageId::kBugcheck ? kGap + 344 : kGap + 210;
            RECT textRc{ kTextLeft, 7, rc.right - kGap, kHeaderHeight };
            const std::wstring kText = state ? (state->title + L" - " + state->statusText) : L"Misc audit";
            ksword::ui::drawTextLine(dc, kText, textRc, ksword::ui::appTheme().mutedTextColor, ksword::ui::systemUiFont(), DT_SINGLELINE | DT_LEFT | DT_VCENTER);
            ::EndPaint(hwnd, &ps);
            return 0;
        }
        case WM_NCDESTROY:
            if (state && state->refreshTask) {
                state->refreshTask->cancel();
            }
            if (state && state->filterTask) {
                state->filterTask->cancel();
            }
            if (state && state->bugcheckUploadTask) {
                state->bugcheckUploadTask->cancel();
            }
            delete state;
            ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
            return 0;
        default:
            break;
        }
        return ::DefWindowProcW(hwnd, msg, wParam, lParam);
    };
    wc.hInstance = ::GetModuleHandleW(nullptr);
    wc.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = ksword::ui::appTheme().panelBrush();
    wc.lpszClassName = kMiscAuditViewClass;
    if (::RegisterClassW(&wc) || ::GetLastError() == ERROR_CLASS_ALREADY_EXISTS) {
        registered = true;
    }
    return registered;
}

// createAuditView creates one retained Misc child page. Inputs are parent,
// bounds, page id and title; processing allocates state for the child window;
// output is the child HWND or nullptr on failure.
HWND createAuditView(HWND parent, const RECT& bounds, MiscAuditPageId pageId, std::wstring title) {
    if (!parent || !registerAuditViewClass()) {
        return nullptr;
    }
    auto* state = new MiscAuditViewState();
    state->pageId = pageId;
    state->title = std::move(title);
    HWND hwnd = ::CreateWindowExW(
        0,
        kMiscAuditViewClass,
        L"MiscAuditView",
        WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN | WS_CLIPSIBLINGS,
        bounds.left,
        bounds.top,
        width(bounds),
        height(bounds),
        parent,
        nullptr,
        ::GetModuleHandleW(nullptr),
        state);
    if (!hwnd) {
        delete state;
    }
    return hwnd;
}

// showHostPages toggles retained tab pages without destroying their state. Input
// is host state; processing uses ShowWindow only; no value is returned.
void showHostPages(MiscFeaturePageState& state) {
    if (state.ciView) {
        ::ShowWindow(state.ciView, state.currentTab == kCiTabIndex ? SW_SHOW : SW_HIDE);
    }
    if (state.vbsView) {
        ::ShowWindow(state.vbsView, state.currentTab == kVbsTabIndex ? SW_SHOW : SW_HIDE);
    }
    if (state.hypervView) {
        ::ShowWindow(state.hypervView, state.currentTab == kHyperVTabIndex ? SW_SHOW : SW_HIDE);
    }
    if (state.appLockerView) {
        ::ShowWindow(state.appLockerView, state.currentTab == kAppLockerTabIndex ? SW_SHOW : SW_HIDE);
    }
    if (state.auxiliaryView) {
        ::ShowWindow(state.auxiliaryView, state.currentTab == kAuxiliaryTabIndex ? SW_SHOW : SW_HIDE);
    }
    if (state.bugcheckView) {
        ::ShowWindow(state.bugcheckView, state.currentTab == kBugcheckTabIndex ? SW_SHOW : SW_HIDE);
    }
    const HWND kCurrentView = state.currentTab == kCiTabIndex ? state.ciView :
        state.currentTab == kVbsTabIndex ? state.vbsView :
        state.currentTab == kHyperVTabIndex ? state.hypervView :
        state.currentTab == kAppLockerTabIndex ? state.appLockerView : state.auxiliaryView;
    ensureAuditViewLoaded(state.currentTab == kBugcheckTabIndex ? state.bugcheckView : kCurrentView);
}

// layoutHostChildren sizes the tab control and every retained child page. Input
// is host state; processing uses the tab display rect; no value is returned.
void layoutHostChildren(MiscFeaturePageState& state) {
    if (!state.hwnd) {
        return;
    }
    RECT rc{};
    ::GetClientRect(state.hwnd, &rc);
    ::MoveWindow(state.tab, 0, 0, width(rc), height(rc), TRUE);
    RECT display = ksword::ui::getTabDisplayRect(state.tab);
    const int kPageWidth = width(display);
    const int kPageHeight = height(display);
    const std::array<HWND, 6> kPages{ state.ciView, state.vbsView, state.hypervView, state.appLockerView, state.auxiliaryView, state.bugcheckView };
    for (HWND page : kPages) {
        if (page) {
            ::MoveWindow(page, display.left, display.top, kPageWidth, kPageHeight, TRUE);
        }
    }
    showHostPages(state);
}

// createHostChildControls creates the tab host and six security posture pages.
// Input is host state with hwnd already assigned; output is true when every page
// was created successfully.
bool createHostChildControls(MiscFeaturePageState& state) {
    state.tab = ksword::ui::createTabControl(state.hwnd, kTabId, 0, 0, 0, 0);
    if (!state.tab) {
        return false;
    }
    ksword::ui::addTabPage(state.tab, kCiTabIndex, { L"Code Integrity / WDAC" });
    ksword::ui::addTabPage(state.tab, kVbsTabIndex, { L"VBS / HVCI / SKCI" });
    ksword::ui::addTabPage(state.tab, kHyperVTabIndex, { L"Hyper-V / VMBus" });
    ksword::ui::addTabPage(state.tab, kAppLockerTabIndex, { L"AppLocker" });
    ksword::ui::addTabPage(state.tab, kAuxiliaryTabIndex, { L"BAM / ahcache" });
    ksword::ui::addTabPage(state.tab, kBugcheckTabIndex, { L"Bugcheck / VMware" });
    ::SendMessageW(state.tab, TCM_SETCURSEL, static_cast<WPARAM>(kCiTabIndex), 0);

    RECT display = ksword::ui::getTabDisplayRect(state.tab);
    const RECT kChildBounds{ 0, 0, std::max(1, width(display)), std::max(1, height(display)) };
    state.ciView = createAuditView(state.tab, kChildBounds, MiscAuditPageId::kCodeIntegrity, L"Code Integrity / WDAC");
    state.vbsView = createAuditView(state.tab, kChildBounds, MiscAuditPageId::kVbsHvciSkci, L"VBS / HVCI / SKCI");
    state.hypervView = createAuditView(state.tab, kChildBounds, MiscAuditPageId::kHyperV, L"Hyper-V / VMBus / HvSocket");
    state.appLockerView = createAuditView(state.tab, kChildBounds, MiscAuditPageId::kAppLocker, L"AppLocker / AppID");
    state.auxiliaryView = createAuditView(state.tab, kChildBounds, MiscAuditPageId::kBamAhcache, L"BAM / ahcache");
    state.bugcheckView = createAuditView(state.tab, kChildBounds, MiscAuditPageId::kBugcheck, L"Bugcheck / VMware branding");
    return state.ciView && state.vbsView && state.hypervView && state.appLockerView && state.auxiliaryView && state.bugcheckView;
}

// registerMiscFeatureClass registers the outer Misc tab host. There is no input;
// output is true when createMiscFeaturePage can create the class.
bool registerMiscFeatureClass() {
    static bool registered = false;
    if (registered) {
        return true;
    }

    WNDCLASSW wc{};
    wc.lpfnWndProc = [](HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) -> LRESULT {
        MiscFeaturePageState* state = stateFromHost(hwnd);
        if (msg == WM_NCCREATE) {
            auto* create = reinterpret_cast<CREATESTRUCTW*>(lParam);
            state = create ? static_cast<MiscFeaturePageState*>(create->lpCreateParams) : nullptr;
            if (state) {
                state->hwnd = hwnd;
                ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(state));
            }
        }

        switch (msg) {
        case WM_CREATE:
            if (state) {
                if (!createHostChildControls(*state)) {
                    delete state;
                    ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
                    return -1;
                }
                layoutHostChildren(*state);
            }
            return 0;
        case WM_SIZE:
            if (state) {
                layoutHostChildren(*state);
            }
            return 0;
        case WM_NOTIFY:
            if (state) {
                const auto* header = reinterpret_cast<const NMHDR*>(lParam);
                if (header && header->hwndFrom == state->tab && header->code == TCN_SELCHANGE) {
                    const LRESULT kSelected = ::SendMessageW(state->tab, TCM_GETCURSEL, 0, 0);
                    if (kSelected >= 0) {
                        state->currentTab = static_cast<int>(kSelected);
                    }
                    showHostPages(*state);
                    return 0;
                }
            }
            break;
        case WM_CTLCOLORSTATIC: {
            HDC dc = reinterpret_cast<HDC>(wParam);
            ::SetBkMode(dc, TRANSPARENT);
            ::SetTextColor(dc, ksword::ui::appTheme().textColor);
            return reinterpret_cast<LRESULT>(ksword::ui::appTheme().windowBrush());
        }
        case WM_NCDESTROY:
            delete state;
            ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
            return 0;
        default:
            break;
        }
        return ::DefWindowProcW(hwnd, msg, wParam, lParam);
    };
    wc.hInstance = ::GetModuleHandleW(nullptr);
    wc.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = ksword::ui::appTheme().windowBrush();
    wc.lpszClassName = kMiscHostClass;
    if (::RegisterClassW(&wc) || ::GetLastError() == ERROR_CLASS_ALREADY_EXISTS) {
        registered = true;
    }
    return registered;
}

} // namespace

HWND createMiscFeaturePage(HWND parent, const RECT& bounds) {
    // Inputs are the shell parent HWND and initial child bounds. Processing only
    // creates the read-only Misc audit host and retained child tabs; registration
    // into FeatureRegistry/vcxproj is intentionally left to thread13 per the user
    // constraint. Return value is the host HWND or nullptr on failure.
    if (!parent || !registerMiscFeatureClass()) {
        return nullptr;
    }
    auto* state = new MiscFeaturePageState();
    HWND hwnd = ::CreateWindowExW(
        0,
        kMiscHostClass,
        L"Misc",
        WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN | WS_CLIPSIBLINGS,
        bounds.left,
        bounds.top,
        width(bounds),
        height(bounds),
        parent,
        nullptr,
        ::GetModuleHandleW(nullptr),
        state);
    if (!hwnd) {
        delete state;
    }
    return hwnd;
}

} // namespace Ksword::Features::Misc

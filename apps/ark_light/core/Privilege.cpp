#include "Privilege.h"

#include "Common.h"
#include "PathUtils.h"

#include <TlHelp32.h>
#include <sddl.h>
#include <shellapi.h>

#include <array>
#include <string>
#include <utility>
#include <vector>

namespace ksword::core {
namespace {
constexpr wchar_t kPrivilegeRestartArgument[] = L"--ksword-privilege-restart";

// appendLine appends one diagnostic line. Inputs are the target text and line;
// processing inserts a newline when needed; no value is returned.
void appendLine(std::wstring& text, const std::wstring& line) {
    if (!text.empty()) {
        text += L"\r\n";
    }
    text += line;
}

// stepFailure formats one Win32 step failure. Inputs are a step name and error
// code; output includes both numeric code and system message.
std::wstring stepFailure(const std::wstring& step, DWORD errorCode) {
    return step + L" failed, error=" + std::to_wstring(errorCode) + L", " + lastErrorMessage(errorCode);
}

// quoteCommandLineArgument quotes one Windows command line argument. Input is
// raw text; processing escapes backslashes before quotes; output is quoted text.
std::wstring quoteCommandLineArgument(const std::wstring& value) {
    std::wstring result = L"\"";
    std::size_t slashCount = 0;
    for (wchar_t ch : value) {
        if (ch == L'\\') {
            ++slashCount;
            result.push_back(ch);
            continue;
        }
        if (ch == L'"') {
            result.append(slashCount, L'\\');
            result.push_back(L'\\');
            result.push_back(ch);
            slashCount = 0;
            continue;
        }
        slashCount = 0;
        result.push_back(ch);
    }
    result.append(slashCount, L'\\');
    result.push_back(L'"');
    return result;
}

// enableTokenPrivilege enables one privilege on an opened token. Inputs are a
// token and privilege name; output is true only when AdjustTokenPrivileges fully
// succeeds.
bool enableTokenPrivilege(HANDLE token, const wchar_t* privilegeName, DWORD* errorOut) {
    if (errorOut) {
        *errorOut = ERROR_SUCCESS;
    }
    if (!token || !privilegeName || privilegeName[0] == L'\0') {
        if (errorOut) {
            *errorOut = ERROR_INVALID_PARAMETER;
        }
        return false;
    }

    LUID luid{};
    if (!::LookupPrivilegeValueW(nullptr, privilegeName, &luid)) {
        if (errorOut) {
            *errorOut = ::GetLastError();
        }
        return false;
    }

    TOKEN_PRIVILEGES privileges{};
    privileges.PrivilegeCount = 1;
    privileges.Privileges[0].Luid = luid;
    privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    ::SetLastError(ERROR_SUCCESS);
    if (!::AdjustTokenPrivileges(token, FALSE, &privileges, sizeof(privileges), nullptr, nullptr)) {
        if (errorOut) {
            *errorOut = ::GetLastError();
        }
        return false;
    }

    const DWORD kAdjustError = ::GetLastError();
    if (kAdjustError != ERROR_SUCCESS) {
        if (errorOut) {
            *errorOut = kAdjustError;
        }
        return false;
    }
    return true;
}

// enableCurrentProcessPrivilege enables one privilege on this process token.
// Input is a privilege name; output is true when the privilege was enabled.
bool enableCurrentProcessPrivilege(const wchar_t* privilegeName, DWORD* errorOut) {
    if (errorOut) {
        *errorOut = ERROR_SUCCESS;
    }

    HANDLE rawToken = nullptr;
    if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &rawToken)) {
        if (errorOut) {
            *errorOut = ::GetLastError();
        }
        return false;
    }
    UniqueHandle token(rawToken);
    return enableTokenPrivilege(token.get(), privilegeName, errorOut);
}

// tryEnablePrivilegeLine tries one privilege and returns a diagnostic line. Input
// is the privilege constant; output is a human-readable status line.
std::wstring tryEnablePrivilegeLine(const wchar_t* privilegeName) {
    DWORD error = ERROR_SUCCESS;
    const bool kOk = enableCurrentProcessPrivilege(privilegeName, &error);
    std::wstring line = privilegeName ? privilegeName : L"<null>";
    line += kOk ? L": enabled" : (L": not enabled (" + std::to_wstring(error) + L", " + lastErrorMessage(error) + L")");
    return line;
}

// queryTokenSessionId queries TokenSessionId. Inputs are token and output slots;
// output is true when session id was read.
bool queryTokenSessionId(HANDLE token, DWORD* sessionIdOut, DWORD* errorOut) {
    if (sessionIdOut) {
        *sessionIdOut = 0;
    }
    if (errorOut) {
        *errorOut = ERROR_SUCCESS;
    }
    if (!token || !sessionIdOut) {
        if (errorOut) {
            *errorOut = ERROR_INVALID_PARAMETER;
        }
        return false;
    }

    DWORD bytes = 0;
    DWORD sessionId = 0;
    if (!::GetTokenInformation(token, TokenSessionId, &sessionId, sizeof(sessionId), &bytes)) {
        if (errorOut) {
            *errorOut = ::GetLastError();
        }
        return false;
    }
    *sessionIdOut = sessionId;
    return true;
}

// tokenBelongsToLocalSystem checks whether a token user SID is LocalSystem.
// Inputs are token and optional error output; output is true for SYSTEM tokens.
bool tokenBelongsToLocalSystem(HANDLE token, DWORD* errorOut) {
    if (errorOut) {
        *errorOut = ERROR_SUCCESS;
    }
    if (!token) {
        if (errorOut) {
            *errorOut = ERROR_INVALID_HANDLE;
        }
        return false;
    }

    DWORD required = 0;
    ::GetTokenInformation(token, TokenUser, nullptr, 0, &required);
    if (required == 0) {
        if (errorOut) {
            *errorOut = ::GetLastError();
        }
        return false;
    }

    std::vector<BYTE> userBuffer(required, 0);
    if (!::GetTokenInformation(token, TokenUser, userBuffer.data(), required, &required)) {
        if (errorOut) {
            *errorOut = ::GetLastError();
        }
        return false;
    }

    std::array<BYTE, SECURITY_MAX_SID_SIZE> systemSid{};
    DWORD sidLength = static_cast<DWORD>(systemSid.size());
    if (!::CreateWellKnownSid(WinLocalSystemSid, nullptr, systemSid.data(), &sidLength)) {
        if (errorOut) {
            *errorOut = ::GetLastError();
        }
        return false;
    }

    const auto* tokenUser = reinterpret_cast<const TOKEN_USER*>(userBuffer.data());
    return ::EqualSid(tokenUser->User.Sid, systemSid.data()) != FALSE;
}

// findSystemProcessTokenCandidate selects the best SYSTEM token source. Inputs
// are the interactive session and output slots; output is true when a candidate
// PID/name/session was found.
bool findSystemProcessTokenCandidate(
    DWORD currentSessionId,
    DWORD* processIdOut,
    std::wstring* processNameOut,
    DWORD* processSessionIdOut,
    std::wstring* detailOut) {
    if (processIdOut) {
        *processIdOut = 0;
    }
    if (processNameOut) {
        processNameOut->clear();
    }
    if (processSessionIdOut) {
        *processSessionIdOut = 0;
    }
    if (detailOut) {
        detailOut->clear();
    }

    UniqueHandle snapshot(::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if (!snapshot.valid()) {
        if (detailOut) {
            *detailOut = stepFailure(L"CreateToolhelp32Snapshot", ::GetLastError());
        }
        return false;
    }

    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (!::Process32FirstW(snapshot.get(), &entry)) {
        if (detailOut) {
            *detailOut = stepFailure(L"Process32FirstW", ::GetLastError());
        }
        return false;
    }

    int bestRank = 0;
    DWORD bestPid = 0;
    DWORD bestSession = 0;
    std::wstring bestName;
    do {
        DWORD session = 0;
        if (!::ProcessIdToSessionId(entry.th32ProcessID, &session)) {
            session = 0;
        }

        const bool kSameSession = session == currentSessionId;
        int rank = 0;
        if (_wcsicmp(entry.szExeFile, L"winlogon.exe") == 0) {
            rank = kSameSession ? 40 : 30;
        } else if (_wcsicmp(entry.szExeFile, L"services.exe") == 0) {
            rank = kSameSession ? 20 : 10;
        }

        if (rank > bestRank) {
            bestRank = rank;
            bestPid = entry.th32ProcessID;
            bestSession = session;
            bestName = entry.szExeFile;
        }
    } while (::Process32NextW(snapshot.get(), &entry));

    if (bestPid == 0) {
        if (detailOut) {
            *detailOut = L"No SYSTEM token source found. Preferred winlogon.exe, then services.exe.";
        }
        return false;
    }

    if (processIdOut) {
        *processIdOut = bestPid;
    }
    if (processNameOut) {
        *processNameOut = bestName;
    }
    if (processSessionIdOut) {
        *processSessionIdOut = bestSession;
    }
    return true;
}

// ScopedThreadImpersonation owns one thread impersonation period. Inputs are an
// impersonation token; processing calls ImpersonateLoggedOnUser/RevertToSelf.
class ScopedThreadImpersonation final : public NonCopyable {
public:
    ScopedThreadImpersonation() = default;
    ~ScopedThreadImpersonation() { reset(); }

    bool impersonate(HANDLE token, DWORD* errorOut) {
        reset();
        if (errorOut) {
            *errorOut = ERROR_SUCCESS;
        }
        if (!::ImpersonateLoggedOnUser(token)) {
            if (errorOut) {
                *errorOut = ::GetLastError();
            }
            return false;
        }
        active_ = true;
        return true;
    }

    void reset() {
        if (active_) {
            ::RevertToSelf();
            active_ = false;
        }
    }

private:
    bool active_ = false;
};
} // namespace

bool isRunningAsAdmin() {
    BOOL elevated = FALSE;
    HANDLE rawToken = nullptr;
    if (::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &rawToken)) {
        UniqueHandle token(rawToken);
        TOKEN_ELEVATION elevation{};
        DWORD bytes = 0;
        if (::GetTokenInformation(token.get(), TokenElevation, &elevation, sizeof(elevation), &bytes)) {
            elevated = elevation.TokenIsElevated != 0;
        }
    }
    if (elevated) {
        return true;
    }

    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    PSID administrators = nullptr;
    if (!::AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &administrators)) {
        return false;
    }
    BOOL isMember = FALSE;
    const BOOL kOk = ::CheckTokenMembership(nullptr, administrators, &isMember);
    ::FreeSid(administrators);
    return kOk && isMember;
}

bool relaunchElevated(const std::wstring& commandLineTail) {
    const std::wstring kExe = modulePath();
    if (kExe.empty()) {
        return false;
    }

    const std::wstring kWorkingDirectory = moduleDirectory();
    SHELLEXECUTEINFOW info{};
    info.cbSize = sizeof(info);
    info.fMask = SEE_MASK_NOCLOSEPROCESS;
    info.lpVerb = L"runas";
    info.lpFile = kExe.c_str();
    info.lpParameters = commandLineTail.empty() ? kPrivilegeRestartArgument : commandLineTail.c_str();
    info.lpDirectory = kWorkingDirectory.empty() ? nullptr : kWorkingDirectory.c_str();
    info.nShow = SW_SHOWNORMAL;
    const BOOL kLaunched = ::ShellExecuteExW(&info);
    if (info.hProcess) {
        ::CloseHandle(info.hProcess);
    }
    return kLaunched != FALSE;
}

bool isUiAccessEnabled() {
    HANDLE rawToken = nullptr;
    if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &rawToken)) {
        return false;
    }
    UniqueHandle token(rawToken);
    DWORD uiAccess = 0;
    DWORD bytes = 0;
    return ::GetTokenInformation(token.get(), TokenUIAccess, &uiAccess, sizeof(uiAccess), &bytes) && uiAccess != 0;
}

std::wstring describePrivilegeState() {
    if (isRunningAsAdmin()) {
        return isUiAccessEnabled() ? L"Admin + UIAccess" : L"Admin";
    }
    return isUiAccessEnabled() ? L"UIAccess" : L"User";
}

std::vector<PrivilegeEnableResult> enableStartupPrivileges() {
    // startupPrivileges is intentionally focused on ARK/driver/process work.
    // Each item is adjusted independently so SeTcbPrivilege or other restricted
    // entries can fail without preventing easier privileges from being enabled.
    static constexpr const wchar_t* kStartupPrivileges[] = {
        SE_DEBUG_NAME,
        SE_LOAD_DRIVER_NAME,
        SE_BACKUP_NAME,
        SE_RESTORE_NAME,
        SE_TAKE_OWNERSHIP_NAME,
        SE_SECURITY_NAME,
        SE_SYSTEM_ENVIRONMENT_NAME,
        SE_INCREASE_QUOTA_NAME,
        SE_ASSIGNPRIMARYTOKEN_NAME,
        SE_TCB_NAME
    };

    constexpr std::size_t kStartupPrivilegeCount = sizeof(kStartupPrivileges) / sizeof(kStartupPrivileges[0]);
    std::vector<PrivilegeEnableResult> results;
    results.reserve(kStartupPrivilegeCount);

    HANDLE rawToken = nullptr;
    if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &rawToken)) {
        const DWORD kError = ::GetLastError();
        for (const wchar_t* privilegeName : kStartupPrivileges) {
            PrivilegeEnableResult result{};
            result.name = privilegeName ? privilegeName : L"<null>";
            result.enabled = false;
            result.errorCode = kError;
            result.message = L"OpenProcessToken failed: " + lastErrorMessage(kError);
            results.push_back(std::move(result));
        }
        return results;
    }

    UniqueHandle token(rawToken);
    for (const wchar_t* privilegeName : kStartupPrivileges) {
        PrivilegeEnableResult result{};
        result.name = privilegeName ? privilegeName : L"<null>";

        DWORD error = ERROR_SUCCESS;
        result.enabled = enableTokenPrivilege(token.get(), privilegeName, &error);
        result.errorCode = error;
        result.message = result.enabled
            ? L"enabled"
            : (L"not enabled (" + std::to_wstring(error) + L", " + lastErrorMessage(error) + L")");
        results.push_back(std::move(result));
    }
    return results;
}

std::wstring summarizePrivilegeEnableResults(const std::vector<PrivilegeEnableResult>& results) {
    // The summary stays deliberately short because it is shown in the status
    // strip/tooltip rather than a modal dialog. Detailed per-item results remain
    // available to callers through PrivilegeEnableResult.
    if (results.empty()) {
        return L"Startup privileges: no attempts.";
    }

    int enabledCount = 0;
    std::wstring failedNames;
    for (const PrivilegeEnableResult& result : results) {
        if (result.enabled) {
            ++enabledCount;
            continue;
        }
        if (!failedNames.empty()) {
            failedNames += L", ";
        }
        failedNames += result.name.empty() ? L"<unknown>" : result.name;
    }

    const int kFailedCount = static_cast<int>(results.size()) - enabledCount;
    std::wstring summary = L"Startup privileges: " + std::to_wstring(enabledCount) + L"/" +
        std::to_wstring(results.size()) + L" enabled";
    if (kFailedCount > 0) {
        summary += L"; failed: " + failedNames;
    }
    return summary;
}

bool launchSelfWithSystemUiAccessToken(std::wstring* detailTextOut) {
    std::wstring detail;
    auto fail = [&](const std::wstring& line) {
        appendLine(detail, line);
        if (detailTextOut) {
            *detailTextOut = detail;
        }
        return false;
    };

    if (!isRunningAsAdmin()) {
        return fail(L"Current process is not elevated. UIAccess fallback needs an elevated administrator token first.");
    }

    appendLine(detail, tryEnablePrivilegeLine(SE_DEBUG_NAME));
    appendLine(detail, tryEnablePrivilegeLine(SE_ASSIGNPRIMARYTOKEN_NAME));
    appendLine(detail, tryEnablePrivilegeLine(SE_INCREASE_QUOTA_NAME));
    appendLine(detail, tryEnablePrivilegeLine(SE_TCB_NAME));

    DWORD currentSession = 0;
    if (!::ProcessIdToSessionId(::GetCurrentProcessId(), &currentSession)) {
        return fail(stepFailure(L"ProcessIdToSessionId(GetCurrentProcessId)", ::GetLastError()));
    }
    appendLine(detail, L"Current SessionId: " + std::to_wstring(currentSession));

    DWORD sourcePid = 0;
    DWORD sourceSession = 0;
    std::wstring sourceName;
    std::wstring findDetail;
    if (!findSystemProcessTokenCandidate(currentSession, &sourcePid, &sourceName, &sourceSession, &findDetail)) {
        return fail(findDetail);
    }
    appendLine(detail, L"SYSTEM token source: " + sourceName + L", PID=" + std::to_wstring(sourcePid) +
        L", SessionId=" + std::to_wstring(sourceSession));

    UniqueHandle sourceProcess(::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, sourcePid));
    if (!sourceProcess.valid()) {
        return fail(stepFailure(L"OpenProcess(" + sourceName + L")", ::GetLastError()));
    }

    HANDLE rawSourceToken = nullptr;
    if (!::OpenProcessToken(sourceProcess.get(), TOKEN_DUPLICATE | TOKEN_QUERY, &rawSourceToken)) {
        return fail(stepFailure(L"OpenProcessToken(" + sourceName + L")", ::GetLastError()));
    }
    UniqueHandle sourceToken(rawSourceToken);

    DWORD tokenUserError = ERROR_SUCCESS;
    if (!tokenBelongsToLocalSystem(sourceToken.get(), &tokenUserError)) {
        return fail(L"Token source is not LocalSystem or cannot be verified: " +
            std::to_wstring(tokenUserError) + L", " + lastErrorMessage(tokenUserError));
    }

    DWORD sourceTokenSession = 0;
    DWORD sourceTokenSessionError = ERROR_SUCCESS;
    if (queryTokenSessionId(sourceToken.get(), &sourceTokenSession, &sourceTokenSessionError)) {
        appendLine(detail, L"Source token SessionId: " + std::to_wstring(sourceTokenSession));
    } else {
        appendLine(detail, L"Source token SessionId query failed: " +
            std::to_wstring(sourceTokenSessionError) + L", " + lastErrorMessage(sourceTokenSessionError));
    }

    SECURITY_ATTRIBUTES security{};
    security.nLength = sizeof(security);
    HANDLE rawImpersonationToken = nullptr;
    if (!::DuplicateTokenEx(sourceToken.get(), MAXIMUM_ALLOWED, &security, SecurityImpersonation,
        TokenImpersonation, &rawImpersonationToken)) {
        return fail(stepFailure(L"DuplicateTokenEx(TokenImpersonation)", ::GetLastError()));
    }
    UniqueHandle impersonationToken(rawImpersonationToken);

    ScopedThreadImpersonation impersonation;
    DWORD impersonationError = ERROR_SUCCESS;
    if (!impersonation.impersonate(impersonationToken.get(), &impersonationError)) {
        return fail(stepFailure(L"ImpersonateLoggedOnUser(SYSTEM)", impersonationError));
    }
    appendLine(detail, L"ImpersonateLoggedOnUser: current thread is temporarily SYSTEM.");

    const wchar_t* tokenPrivileges[] = { SE_ASSIGNPRIMARYTOKEN_NAME, SE_INCREASE_QUOTA_NAME, SE_TCB_NAME };
    for (const wchar_t* privilege : tokenPrivileges) {
        DWORD error = ERROR_SUCCESS;
        const bool kOk = enableTokenPrivilege(impersonationToken.get(), privilege, &error);
        appendLine(detail, std::wstring(L"SYSTEM impersonation token ") + privilege +
            (kOk ? L": enabled" : (L": not enabled (" + std::to_wstring(error) + L", " + lastErrorMessage(error) + L")")));
    }

    HANDLE rawPrimaryToken = nullptr;
    if (!::DuplicateTokenEx(sourceToken.get(), MAXIMUM_ALLOWED, &security, SecurityImpersonation,
        TokenPrimary, &rawPrimaryToken)) {
        return fail(stepFailure(L"DuplicateTokenEx(TokenPrimary)", ::GetLastError()));
    }
    UniqueHandle primaryToken(rawPrimaryToken);
    appendLine(detail, L"DuplicateTokenEx: SYSTEM primary token duplicated.");

    for (const wchar_t* privilege : tokenPrivileges) {
        DWORD error = ERROR_SUCCESS;
        const bool kOk = enableTokenPrivilege(primaryToken.get(), privilege, &error);
        appendLine(detail, std::wstring(L"Duplicated token ") + privilege +
            (kOk ? L": enabled" : (L": not enabled (" + std::to_wstring(error) + L", " + lastErrorMessage(error) + L")")));
    }

    if (sourceSession != currentSession) {
        DWORD sessionForToken = currentSession;
        if (!::SetTokenInformation(primaryToken.get(), TokenSessionId, &sessionForToken, sizeof(sessionForToken))) {
            return fail(stepFailure(L"SetTokenInformation(TokenSessionId)", ::GetLastError()));
        }
        appendLine(detail, L"SetTokenInformation(TokenSessionId): " + std::to_wstring(currentSession));
    }

    DWORD uiAccess = 1;
    if (!::SetTokenInformation(primaryToken.get(), TokenUIAccess, &uiAccess, sizeof(uiAccess))) {
        return fail(stepFailure(L"SetTokenInformation(TokenUIAccess)", ::GetLastError()));
    }
    appendLine(detail, L"SetTokenInformation(TokenUIAccess): requested.");

    DWORD verifiedUiAccess = 0;
    DWORD verifiedBytes = 0;
    if (!::GetTokenInformation(primaryToken.get(), TokenUIAccess, &verifiedUiAccess, sizeof(verifiedUiAccess), &verifiedBytes) ||
        verifiedUiAccess == 0) {
        return fail(stepFailure(L"GetTokenInformation(TokenUIAccess verify)", ::GetLastError()));
    }
    appendLine(detail, L"TokenUIAccess verify: enabled.");

    const std::wstring kSelf = modulePath();
    if (kSelf.empty()) {
        return fail(L"Get current module path failed.");
    }

    std::wstring commandLine = quoteCommandLineArgument(kSelf) + L" " + kPrivilegeRestartArgument;
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    wchar_t desktop[] = L"winsta0\\default";
    startup.lpDesktop = desktop;

    PROCESS_INFORMATION process{};
    const BOOL kCreated = ::CreateProcessAsUserW(primaryToken.get(), kSelf.c_str(), commandLine.data(),
        nullptr, nullptr, FALSE, CREATE_NEW_CONSOLE | CREATE_UNICODE_ENVIRONMENT, nullptr, nullptr, &startup, &process);
    if (!kCreated) {
        return fail(stepFailure(L"CreateProcessAsUserW", ::GetLastError()));
    }

    UniqueHandle newProcess(process.hProcess);
    UniqueHandle newThread(process.hThread);
    appendLine(detail, L"CreateProcessAsUserW: new instance started, PID=" + std::to_wstring(process.dwProcessId));
    impersonation.reset();
    appendLine(detail, L"RevertToSelf: SYSTEM impersonation released.");

    if (detailTextOut) {
        *detailTextOut = detail;
    }
    return true;
}

} // namespace Ksword::Core

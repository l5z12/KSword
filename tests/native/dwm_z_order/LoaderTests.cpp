#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#include <TlHelp32.h>
#include <string>
#include <iostream>
#include "../../../shared/window/DwmRemoteLoader.h"
#include "../../../shared/window/DwmProcessIdentity.h"
#include "../../../apps/desktop/other_dock/DwmAgentDeployment.h"

ks::dwm_order::transport::PreparedAgent runDeploymentTests(void (*check)(bool, const char*), const wchar_t* agentPath);

void runLoaderTests(void (*check)(bool, const char*), const wchar_t* agentPath)
{
    wchar_t executable[32768]{};
    GetModuleFileNameW(nullptr, executable, 32768);
    const std::wstring kExecutablePath(executable);
    const auto kDirectory = kExecutablePath.substr(0, kExecutablePath.find_last_of(L'\\') + 1);
    const auto kFixturePath = kDirectory + L"DwmLoaderFixture.dll";
    HANDLE token = nullptr, identification = nullptr;
    const bool kTokenReady = OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &token)
        && DuplicateTokenEx(token, TOKEN_QUERY | TOKEN_IMPERSONATE, nullptr, SecurityIdentification,
            TokenImpersonation, &identification);
    check(kTokenReady, "create identification-only token to reproduce the former loader failure");
    if (kTokenReady)
    {
        const bool kAssigned = SetThreadToken(nullptr, identification) != FALSE;
        check(kAssigned, "assign identification-only token to the test thread");
        if (kAssigned)
        {
            HMODULE local = LoadLibraryExW(kFixturePath.c_str(), nullptr,
                LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
            const DWORD kLocalError = GetLastError();
            const BOOL kRestored = RevertToSelf();
            std::cout << "LOADER_CASE=identification WIN32=" << kLocalError << '\n';
            // Access checks can reject the load before the impersonation-level check.
            // Both errors preserve the invariant: an identification-only token cannot load the fixture.
            check(!local && (kLocalError == ERROR_BAD_IMPERSONATION_LEVEL || kLocalError == ERROR_ACCESS_DENIED),
                "identification-only impersonation prevents loading the fixture");
            check(kRestored != FALSE, "restore test thread identity after the denied load");
            if (local) FreeLibrary(local);
        }
    }
    if (identification) CloseHandle(identification);
    if (token) CloseHandle(token);
    auto prepared = runDeploymentTests(check, agentPath);
    if (prepared.path.empty()) return;

    SECURITY_ATTRIBUTES attributes{sizeof(attributes), nullptr, TRUE};
    HANDLE finished = CreateEventW(&attributes, TRUE, FALSE, nullptr);
    HANDLE ready = CreateEventW(&attributes, TRUE, FALSE, nullptr);
    check(finished && ready, "create child readiness and lifetime events");
    if (!finished || !ready)
    {
        if (finished) CloseHandle(finished);
        if (ready) CloseHandle(ready);
        return;
    }
    std::wstring command = L"\"" + kExecutablePath + L"\" --loader-child "
        + std::to_wstring(reinterpret_cast<std::uintptr_t>(finished)) + L" "
        + std::to_wstring(reinterpret_cast<std::uintptr_t>(ready));
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION child{};
    const BOOL kCreated = CreateProcessW(executable, command.data(), nullptr, nullptr, TRUE,
        CREATE_NO_WINDOW, nullptr, kDirectory.c_str(), &startup, &child);
    check(kCreated != FALSE, "create disposable loader test process");
    if (!kCreated) { CloseHandle(finished); CloseHandle(ready); return; }
    CloseHandle(child.hThread);
    const bool kStarted = WaitForSingleObject(ready, 5000) == WAIT_OBJECT_0;
    check(kStarted, "child has initialized before remote loader tests");
    CloseHandle(ready);
    if (!kStarted)
    {
        SetEvent(finished);
        WaitForSingleObject(child.hProcess, 5000);
        CloseHandle(child.hProcess);
        CloseHandle(finished);
        return;
    }
    using ks::dwm_order::transport::loadAgent;
    const auto kReport = [](const char* name, const ks::dwm_order::transport::LoadResult& value)
    {
        std::cout << "LOADER_CASE=" << name << " WIN32=" << value.error
            << " THREAD=" << value.threadExitCode << " COMPLETED=" << value.loaderCompleted
            << " MODULE=" << value.module << '\n';
    };
    const auto kMissing = loadAgent(child.hProcess, child.dwProcessId, kDirectory + L"missing-DWM-loader-test.dll");
    kReport("missing", kMissing);
    check(kMissing.loaderCompleted && kMissing.error == ERROR_MOD_NOT_FOUND && !kMissing.module,
        "missing DLL returns loader error 126 instead of a fabricated 1114");
    const auto kRejected = loadAgent(child.hProcess, child.dwProcessId, kDirectory + L"DwmLoaderReject.dll");
    kReport("rejected", kRejected);
    check(kRejected.loaderCompleted && kRejected.error == ERROR_DLL_INIT_FAILED && !kRejected.module,
        "a genuine DllMain rejection retains loader error 1114");
    const auto kLoaded = loadAgent(child.hProcess, child.dwProcessId, kFixturePath);
    kReport("process-identity", kLoaded);
    check(kLoaded.loaderCompleted && !kLoaded.error && !kLoaded.threadExitCode && kLoaded.module,
        "remote loader runs as the target process without any impersonation token");
    const auto kAgent = loadAgent(child.hProcess, child.dwProcessId, prepared.path, prepared.lease);
    kReport("agent", kAgent);
    check(kAgent.loaderCompleted && !kAgent.error && !kAgent.threadExitCode && kAgent.module,
        "production agent loads through the production cross-process transport");

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, child.dwProcessId);
    bool matched = false;
    if (snapshot != INVALID_HANDLE_VALUE)
    {
        MODULEENTRY32W entry{};
        entry.dwSize = sizeof(entry);
        if (Module32FirstW(snapshot, &entry)) do
        {
            if (lstrcmpiW(entry.szModule, L"KswordDwmZOrder.dll") == 0)
                matched = reinterpret_cast<std::uintptr_t>(entry.modBaseAddr) == kAgent.module;
        } while (Module32NextW(snapshot, &entry));
        CloseHandle(snapshot);
    }
    check(matched, "receipt preserves the complete remote HMODULE and matches the module list");
    using ks::dwm_order::matchesProcessIdentity;
    ks::dwm_order::WindowIdentity identity;
    identity.processId = child.dwProcessId;
    FILETIME time{}, exit{}, kernel{}, user{};
    const bool kTimesRead = GetProcessTimes(child.hProcess, &time, &exit, &kernel, &user) != FALSE;
    identity.processCreated = (static_cast<std::uint64_t>(time.dwHighDateTime) << 32) | time.dwLowDateTime;
    HANDLE query = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, child.dwProcessId);
    check(kTimesRead && query && matchesProcessIdentity(query, identity),
        "query-only process handle validates the original process identity");
    check(!matchesProcessIdentity(GetCurrentProcess(), identity), "different process handle is rejected");
    ++identity.processCreated;
    check(!matchesProcessIdentity(query, identity), "mismatched process creation time is rejected");
    --identity.processCreated;
    HANDLE unexpectedToken = nullptr;
    const BOOL kImpersonating = OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &unexpectedToken);
    check(!kImpersonating && GetLastError() == ERROR_NO_TOKEN, "caller thread identity is unchanged after loading");
    if (unexpectedToken) CloseHandle(unexpectedToken);
    SetEvent(finished);
    check(WaitForSingleObject(child.hProcess, 5000) == WAIT_OBJECT_0, "test child exits normally without termination");
    check(!matchesProcessIdentity(query, identity), "terminated process handle is rejected even with the original PID");
    if (query) CloseHandle(query);
    CloseHandle(child.hProcess);
    CloseHandle(finished);
}

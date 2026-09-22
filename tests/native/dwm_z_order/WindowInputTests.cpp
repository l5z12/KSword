#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#include "../../../apps/desktop/other_dock/WindowInputClient.h"
#include "../../../shared/ark_client/ArkDriverClient.h"
#include <cstdio>
#include <cstdlib>
#include <string>

namespace
{
    using namespace ks::window_input;
    using ks::dwm_order::WindowIdentity;
    enum class DwmBehavior { kReady, kMissing, kApplyFailure, kRestoreFailure, kBusy };
    DwmBehavior behavior = DwmBehavior::kReady;
    std::uint64_t maintained = 0;
    int dwmCalls = 0;
    int failures = 0;
    ULONG fixtureBand = 1;
    bool kernelFails = false, kernelRestoreFails = false;
    int kernelCalls = 0;

    void check(bool ok, const char* name)
    {
        if (!ok) { std::printf("FAIL: %s (Win32 %lu)\n", name, GetLastError()); ++failures; }
    }

    struct HostWindows { HWND normal, child, layered, ownDc; };

    int host()
    {
        WNDCLASSW cls{};
        cls.hInstance = GetModuleHandleW(nullptr);
        cls.lpfnWndProc = DefWindowProcW;
        cls.lpszClassName = L"WindowInputTestHost";
        if (!RegisterClassW(&cls)) return 2;
        HostWindows windows{};
        // Off-screen fixtures never overlap the user's windows.
        windows.normal = CreateWindowExW(0, cls.lpszClassName, L"Input fixture", WS_POPUP | WS_VISIBLE,
            -30000, -30000, 32, 32, nullptr, nullptr, cls.hInstance, nullptr);
        windows.child = CreateWindowExW(0, cls.lpszClassName, L"Child fixture", WS_CHILD,
            0, 0, 8, 8, windows.normal, nullptr, cls.hInstance, nullptr);
        windows.layered = CreateWindowExW(WS_EX_LAYERED, cls.lpszClassName, L"Layered fixture", WS_POPUP,
            -30000, -30000, 32, 32, nullptr, nullptr, cls.hInstance, nullptr);
        SetLayeredWindowAttributes(windows.layered, RGB(1, 2, 3), 123, LWA_ALPHA | LWA_COLORKEY);
        cls.style = CS_OWNDC;
        cls.lpszClassName = L"WindowInputTestOwnDC";
        if (!RegisterClassW(&cls)) return 3;
        windows.ownDc = CreateWindowExW(0, cls.lpszClassName, L"DC fixture", WS_POPUP,
            -30000, -30000, 32, 32, nullptr, nullptr, cls.hInstance, nullptr);
        if (!windows.normal || !windows.child || !windows.layered || !windows.ownDc) return 4;
        DWORD written = 0;
        if (!WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), &windows, sizeof(windows), &written, nullptr)
            || written != sizeof(windows)) return 5;
        MSG message{};
        while (GetMessageW(&message, nullptr, 0, 0) > 0)
        { TranslateMessage(&message); DispatchMessageW(&message); }
        for (HWND hwnd : {windows.child, windows.normal, windows.layered, windows.ownDc}) DestroyWindow(hwnd);
        return 0;
    }

    WindowIdentity identity(HWND hwnd)
    {
        WindowIdentity identity;
        std::uint32_t error = 0;
        check(capture(reinterpret_cast<std::uint64_t>(hwnd), identity, error), "capture fixture identity");
        return identity;
    }

    int CALLBACK removeInputMarker(HWND hwnd, LPWSTR name, HANDLE, ULONG_PTR)
    {
        if (IS_INTRESOURCE(name)) return 1;
        if (std::wstring(name).find(L"KSword.WindowInput.") == 0) RemovePropW(hwnd, name);
        return 1;
    }
}

// Deliberate R0 stub: tests never open a driver or mutate kernel memory.
namespace ksword::ark
{
    WindowBandResult DriverClient::controlWindowBand(KSWORD_ARK_WINDOW_BAND_REQUEST q) const
    {
        ++kernelCalls;
        WindowBandResult r;
        r.io.ok = true;
        r.response.size = sizeof(r.response);
        r.response.version = KSWORD_ARK_WINDOW_BAND_VERSION;
        r.response.flags = KSW_BAND_VERIFIED | KSW_BAND_POSITION_VERIFIED;
        r.response.previousBand = r.response.currentBand = fixtureBand;
        r.response.windowObject = q.hwnd ^ 0xA51200000000ULL;
        if (q.operation == KSW_BAND_SET)
        {
            check(q.confirmation == KSW_BAND_CONFIRMED && q.expectedBand == fixtureBand &&
                q.expectedObject == r.response.windowObject, "band mutation uses queried identity and expected band");
            if (kernelFails || (kernelRestoreFails && q.newBand == 1))
            { r.response.lastStatus = static_cast<LONG>(0xC0000001); r.response.flags = 0; }
            else
            {
                fixtureBand = q.newBand;
                r.response.currentBand = fixtureBand;
                SetWindowPos(reinterpret_cast<HWND>(q.hwnd), HWND_TOPMOST, 0, 0, 0, 0,
                    SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
            }
        }
        return r;
    }
}

// This test binary never opens or injects into DWM. These receipts exercise
// native-input rollback and ownership without running the compositor agent.
namespace ks::dwm_order
{
    std::recursive_mutex& operationMutex() { static std::recursive_mutex lock; return lock; }
    Reply executeRequest(const Request& request, const std::wstring&, bool allowLoad)
    {
        ++dwmCalls;
        check(!allowLoad, "window settings must not inject DWM");
        Reply reply;
        reply.response.status = Status::kOk;
        reply.response.flags = kVerified;
        if (behavior == DwmBehavior::kMissing) reply.response.status = Status::kNotRunning;
        else if (request.action == Action::kApply)
        {
            if (behavior == DwmBehavior::kApplyFailure) reply.response.status = Status::kNativeFailure;
            else maintained = request.target.hwnd;
        }
        else if (request.action == Action::kRestore)
        {
            if (behavior == DwmBehavior::kRestoreFailure) reply.response.status = Status::kTimeout;
            else maintained = 0;
        }
        if (maintained || behavior == DwmBehavior::kBusy)
        { reply.response.flags |= kMaintaining; reply.response.maintainedWindow = maintained ? maintained : 123; }
        return reply;
    }
}

int wmain(int argc, wchar_t** argv)
{
    if (argc == 2 && std::wstring(argv[1]) == L"--host") return host();
    SECURITY_ATTRIBUTES security{sizeof(security), nullptr, TRUE};
    HANDLE readPipe = nullptr, writePipe = nullptr;
    if (!CreatePipe(&readPipe, &writePipe, &security, 0)) return 2;
    SetHandleInformation(readPipe, HANDLE_FLAG_INHERIT, 0);
    wchar_t exe[32768]{};
    GetModuleFileNameW(nullptr, exe, static_cast<DWORD>(std::size(exe)));
    std::wstring command = L"\"" + std::wstring(exe) + L"\" --host";
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdOutput = writePipe;
    startup.hStdError = writePipe;
    startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    PROCESS_INFORMATION process{};
    if (!CreateProcessW(exe, command.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW,
        nullptr, nullptr, &startup, &process)) return 3;
    CloseHandle(writePipe);
    HostWindows windows{};
    DWORD read = 0;
    const bool kHostReady = ReadFile(readPipe, &windows, sizeof(windows), &read, nullptr) && read == sizeof(windows);
    CloseHandle(readPipe);
    check(kHostReady, "fixture startup");
    if (kHostReady)
    {
        const auto kNormal = identity(windows.normal), kChild = identity(windows.child);
        const auto kLayered = identity(windows.layered), kOwnDc = identity(windows.ownDc);
        check(apply(kNormal, Mode::kDisabled, L"").status == Status::kOk, "disable normal window");
        check(!IsWindowEnabled(windows.normal), "disabled readback");
        EnableWindow(windows.normal, TRUE);
        check(apply(kNormal, Mode::kDisabled, L"").status == Status::kOk
            && !IsWindowEnabled(windows.normal), "repeat apply repairs externally changed state");
        auto wrong = kNormal;
        ++wrong.processCreated;
        check(restore(wrong, L"").status == Status::kInvalidWindow, "reject stale restore identity");
        check(!IsWindowEnabled(windows.normal), "stale restore made no change");
        check(restore(kNormal, L"").status == Status::kOk && IsWindowEnabled(windows.normal), "restore enabled state");

        check(apply(kChild, Mode::kDisabled, L"").status == Status::kOk && !IsWindowEnabled(windows.child), "disable child window");
        check(restore(kChild, L"").status == Status::kOk && IsWindowEnabled(windows.child), "restore child window");

        const auto kOriginalEx = GetWindowLongPtrW(windows.normal, GWL_EXSTYLE);
        check(apply(kNormal, Mode::kClickThrough, L"").status == Status::kOk, "apply layered pass-through");
        check(query(kNormal).clickThrough, "pass-through readback");
        SetWindowLongPtrW(windows.normal, GWL_EXSTYLE, GetWindowLongPtrW(windows.normal, GWL_EXSTYLE) | WS_EX_TOOLWINDOW);
        check(restore(kNormal, L"").status == Status::kOk, "restore pass-through");
        check(GetWindowLongPtrW(windows.normal, GWL_EXSTYLE) == (kOriginalEx | WS_EX_TOOLWINDOW), "preserve unrelated style changes");

        check(apply(kLayered, Mode::kClickThrough, L"").status == Status::kOk, "pass-through on existing layered window");
        check(restore(kLayered, L"").status == Status::kOk, "restore existing layered window");
        COLORREF color = 0;
        BYTE alpha = 0;
        DWORD flags = 0;
        check(GetLayeredWindowAttributes(windows.layered, &color, &alpha, &flags)
            && color == RGB(1, 2, 3) && alpha == 123 && flags == (LWA_ALPHA | LWA_COLORKEY), "preserve original alpha and color key");
        check(apply(kOwnDc, Mode::kClickThrough, L"").status == Status::kUnsupportedWindow, "reject unsupported layered class");
        check(dwmCalls == 0, "basic input modes do not access DWM");
        check(kernelCalls == 0, "basic input modes do not access Win32k");

        behavior = DwmBehavior::kMissing;
        check(apply(kNormal, Mode::kCovered, L"").status == Status::kDwmFailure, "covered mode requires preloaded agent");
        check(!(GetWindowLongPtrW(windows.normal, GWL_EXSTYLE) & WS_EX_TOPMOST), "missing agent leaves native order alone");
        behavior = DwmBehavior::kBusy;
        check(apply(kNormal, Mode::kCovered, L"").status == Status::kOrderInUse, "do not replace another maintained window");
        behavior = DwmBehavior::kApplyFailure;
        check(apply(kNormal, Mode::kCovered, L"").status == Status::kDwmFailure, "failed DWM apply is reported");
        check(!(GetWindowLongPtrW(windows.normal, GWL_EXSTYLE) & WS_EX_TOPMOST), "failed DWM apply rolls back native topmost");
        check(!query(kNormal).managed, "successful rollback removes saved record");
        behavior = DwmBehavior::kReady;
        check(apply(kNormal, Mode::kCovered, L"").status == Status::kOk && hasCoveredWindow(), "covered mode transaction");
        check(GetWindowLongPtrW(windows.normal, GWL_EXSTYLE) & WS_EX_TOPMOST, "covered mode uses real native topmost");
        maintained = 0;
        check(query(kNormal).status == Status::kOrderChanged, "query detects lost DWM maintenance");
        maintained = kNormal.hwnd;
        behavior = DwmBehavior::kRestoreFailure;
        check(restore(kNormal, L"").status == Status::kRestoreFailed && hasCoveredWindow(), "retain incomplete restoration");
        behavior = DwmBehavior::kReady;
        check(restore(kNormal, L"").status == Status::kOk && !hasCoveredWindow(), "retry incomplete restoration");
        check(!restore(kNormal, L"").restored, "no saved record is not reported as restored");

        check(apply(kNormal, Mode::kDisabled, L"").status == Status::kOk, "prepare lifetime marker case");
        EnumPropsExW(windows.normal, removeInputMarker, 0);
        restoreAll(L"");
        check(!IsWindowEnabled(windows.normal), "lost lifetime marker prevents stale restoration");
        EnableWindow(windows.normal, TRUE);
        check(apply(kNormal, Mode::kClickThrough, L"").status == Status::kOk, "prepare restore all pass-through");
        check(apply(kChild, Mode::kDisabled, L"").status == Status::kOk, "prepare restore all disabled child");
        check(restoreAll(L"").status == Status::kOk, "restore all input settings");
        check(IsWindowEnabled(windows.child) && !query(kNormal).clickThrough, "restore all readback");

        const int kBeforeDwm = dwmCalls;
        check(apply(kNormal, Mode::kUiAccessFront, L"").status == Status::kOk && fixtureBand == 2,
            "native UIAccess front works without a prior enable or probe");
        check(queryBandSupport().status == Status::kOk && fixtureBand == 2, "optional support query does not alter band");
        check(dwmCalls == kBeforeDwm, "native band order does not depend on DWM injection");
        check(query(kNormal).band == 2, "read native band");
        kernelRestoreFails = true;
        check(restore(kNormal, L"").status == Status::kRestoreFailed && query(kNormal).managed, "retain failed band restore");
        kernelRestoreFails = false;
        check(restore(kNormal, L"").status == Status::kOk && fixtureBand == 1, "restore original band");
        check(!(GetWindowLongPtrW(windows.normal, GWL_EXSTYLE) & WS_EX_TOPMOST), "restore original native topmost after band restore");
        behavior = DwmBehavior::kApplyFailure;
        check(apply(kNormal, Mode::kUiAccessCovered, L"").status == Status::kDwmFailure && fixtureBand == 1,
            "failed compositor mode rolls back native band");
        behavior = DwmBehavior::kReady;
        check(apply(kNormal, Mode::kUiAccessBack, L"").status == Status::kOk, "UIAccess band back");
        check(restoreAll(L"").status == Status::kOk && fixtureBand == 1, "global restore includes native band");
        kernelFails = true;
        check(apply(kNormal, Mode::kUiAccessFront, L"").status == Status::kRestoreFailed, "kernel errors never report success");
        kernelFails = false;
        check(restoreAll(L"").status == Status::kOk, "retry recovery after kernel failure");
    }
    PostThreadMessageW(process.dwThreadId, WM_QUIT, 0, 0);
    if (WaitForSingleObject(process.hProcess, 5000) != WAIT_OBJECT_0) TerminateProcess(process.hProcess, 4);
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    std::printf("Window input tests: %s\n", failures ? "FAILED" : "PASS");
    return failures ? 1 : 0;
}

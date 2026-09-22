#include "MainWindow.h"

#include "../core/Privilege.h"

#include "../core/Win32Lean.h"

#include <string>

namespace {

// traceStartupStep writes one millisecond timing line to the debugger. Inputs
// are the step name plus the measured duration; processing is non-modal and
// intentionally avoids MessageBoxW so it does not perturb UAC timing; no value
// is returned.
void traceStartupStep(const wchar_t* step, const ULONGLONG elapsedMs) {
    std::wstring line = L"[KswordARKLight startup] ";
    line += step ? step : L"<unknown>";
    line += L": ";
    line += std::to_wstring(elapsedMs);
    line += L" ms\r\n";
    ::OutputDebugStringW(line.c_str());
}

// traceStartupText writes one startup status line. Input is static diagnostic
// text; processing goes only to the debugger output stream; no value is
// returned.
void traceStartupText(const wchar_t* text) {
    std::wstring line = L"[KswordARKLight startup] ";
    line += text ? text : L"<null>";
    line += L"\r\n";
    ::OutputDebugStringW(line.c_str());
}

} // namespace

// wWinMain is the pure Win32 process entry point. Inputs are the standard Win32
// instance/show parameters; processing optionally relaunches elevated, creates
// the main shell, and enters the message loop; output is the process exit code.
int APIENTRY wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int showCommand) {
    const ULONGLONG kAfterProbeMessage = ::GetTickCount64();
    const bool kRunningAsAdmin = ksword::core::isRunningAsAdmin();
    traceStartupStep(L"IsRunningAsAdmin", ::GetTickCount64() - kAfterProbeMessage);

    if (!kRunningAsAdmin) {
        const ULONGLONG kBeforeRunas = ::GetTickCount64();
        traceStartupText(L"calling ShellExecuteExW(runas)");
        if (ksword::core::relaunchElevated()) {
            traceStartupStep(L"RelaunchElevated returned success", ::GetTickCount64() - kBeforeRunas);
            return 0;
        }
        traceStartupStep(L"RelaunchElevated returned failure/cancel", ::GetTickCount64() - kBeforeRunas);
    }

    const ULONGLONG kBeforeMainWindowCreate = ::GetTickCount64();
    ksword::app::MainWindow window;
    if (!window.create(instance, showCommand)) {
        ::MessageBoxW(nullptr, L"Failed to create KswordARKLight main window.", L"KswordARKLight", MB_ICONERROR | MB_OK);
        return 1;
    }
    traceStartupStep(L"MainWindow::create", ::GetTickCount64() - kBeforeMainWindowCreate);
    return window.run();
}

#include "../../shared/ark_client/ArkDriverClient.h"

#include <Windows.h>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cwchar>
#include <fstream>
#include <string>
#include <thread>
#include <vector>

namespace
{
    constexpr wchar_t kPluginTitle[] = L"KSword Cheat Engine";
    constexpr wchar_t kTabWindowClass[] = L"KSwordCheatEngineTabSurface";
    constexpr char kProtocol[] = "ksword-plugin/1";
    constexpr char kPluginId[] = "cheat-engine";
    constexpr UINT kInitializeTabMessage = WM_APP + 1U;
    constexpr UINT_PTR kLifecycleTimerId = 1U;

    struct ParsedArguments
    {
        std::wstring command;
        DWORD targetProcessId = 0U;
        HWND parentWindow = nullptr;
        DWORD hostProcessId = 0U;
        bool valid = false;
    };

    enum class BridgeStatus
    {
        kReady,
        kFailed,
        kTimeout,
        kLaunchFailed
    };

    HWND gTabWindow = nullptr;
    HWND gCheatEngineWindow = nullptr;
    HANDLE gCheatEngineProcess = nullptr;
    DWORD gHostProcessId = 0U;
    int gTabExitCode = 0;

    void emitJsonLine(const std::string& eventName, const std::string& fields)
    {
        std::string line =
            "{\"protocol\":\"" + std::string(kProtocol) +
            "\",\"plugin_id\":\"" + std::string(kPluginId) +
            "\",\"event\":\"" + eventName + "\"";
        if (!fields.empty())
        {
            line += ",";
            line += fields;
        }
        line += "}\n";

        const HANDLE kStdoutHandle = ::GetStdHandle(STD_OUTPUT_HANDLE);
        if (kStdoutHandle == nullptr || kStdoutHandle == INVALID_HANDLE_VALUE)
        {
            return;
        }
        DWORD written = 0U;
        (void)::WriteFile(
            kStdoutHandle,
            line.data(),
            static_cast<DWORD>(line.size()),
            &written,
            nullptr);
    }

    void emitError(const char* const code, const char* const message)
    {
        emitJsonLine(
            "error",
            "\"code\":\"" + std::string(code) +
            "\",\"message\":\"" + std::string(message) + "\"");
    }

    bool parseUnsignedProcessId(const std::wstring& text, DWORD* const valueOut)
    {
        if (valueOut == nullptr || text.empty())
        {
            return false;
        }
        wchar_t* end = nullptr;
        errno = 0;
        const unsigned long long kValue = std::wcstoull(text.c_str(), &end, 10);
        if (errno != 0 || end == text.c_str() || *end != L'\0' ||
            kValue == 0ULL || kValue > static_cast<unsigned long long>(MAXDWORD))
        {
            return false;
        }
        *valueOut = static_cast<DWORD>(kValue);
        return true;
    }

    bool parseWindowHandle(const std::wstring& text, HWND* const valueOut)
    {
        if (valueOut == nullptr || text.empty())
        {
            return false;
        }
        wchar_t* end = nullptr;
        errno = 0;
        const unsigned long long kValue = std::wcstoull(text.c_str(), &end, 10);
        if (errno != 0 || end == text.c_str() || *end != L'\0' || kValue == 0ULL)
        {
            return false;
        }
        const auto kNumericHandle = static_cast<std::uintptr_t>(kValue);
        if (static_cast<unsigned long long>(kNumericHandle) != kValue)
        {
            return false;
        }
        *valueOut = reinterpret_cast<HWND>(kNumericHandle);
        return true;
    }

    ParsedArguments parseArguments(const int argc, wchar_t* const argv[])
    {
        ParsedArguments parsed;
        if (argc < 3 || std::wstring(argv[1]) != L"--ksword-plugin")
        {
            return parsed;
        }
        parsed.command = argv[2];
        if (parsed.command == L"info" || parsed.command == L"check")
        {
            parsed.valid = true;
            return parsed;
        }
        if (parsed.command != L"launch" && parsed.command != L"tab")
        {
            return parsed;
        }

        for (int index = 3; index + 1 < argc; ++index)
        {
            const std::wstring kArgument = argv[index];
            if (kArgument == L"--pid")
            {
                if (!parseUnsignedProcessId(
                        argv[index + 1],
                        &parsed.targetProcessId))
                {
                    return parsed;
                }
                ++index;
            }
            else if (kArgument == L"--parent-hwnd")
            {
                if (!parseWindowHandle(argv[index + 1], &parsed.parentWindow))
                {
                    return parsed;
                }
                ++index;
            }
            else if (kArgument == L"--host-pid")
            {
                if (!parseUnsignedProcessId(
                        argv[index + 1],
                        &parsed.hostProcessId))
                {
                    return parsed;
                }
                ++index;
            }
        }
        if (parsed.command == L"launch")
        {
            parsed.valid = parsed.targetProcessId != 0U;
            return parsed;
        }

        DWORD parentOwnerProcessId = 0U;
        if (parsed.parentWindow == nullptr ||
            parsed.hostProcessId == 0U ||
            !::IsWindow(parsed.parentWindow) ||
            ::GetWindowThreadProcessId(
                parsed.parentWindow,
                &parentOwnerProcessId) == 0U ||
            parentOwnerProcessId != parsed.hostProcessId)
        {
            return parsed;
        }
        parsed.valid = true;
        return parsed;
    }

    std::wstring currentExecutablePath()
    {
        std::vector<wchar_t> buffer(32768U, L'\0');
        const DWORD kLength = ::GetModuleFileNameW(
            nullptr,
            buffer.data(),
            static_cast<DWORD>(buffer.size()));
        if (kLength == 0U || kLength >= static_cast<DWORD>(buffer.size()))
        {
            return {};
        }
        return std::wstring(buffer.data(), kLength);
    }

    std::wstring parentDirectory(const std::wstring& path)
    {
        const std::wstring::size_type kSeparator = path.find_last_of(L"\\/");
        if (kSeparator == std::wstring::npos)
        {
            return {};
        }
        return path.substr(0U, kSeparator);
    }

    std::wstring joinPath(
        const std::wstring& directory,
        const std::wstring& relativePath)
    {
        if (directory.empty())
        {
            return relativePath;
        }
        return directory + L"\\" + relativePath;
    }

    bool isDriverReady()
    {
        const ksword::ark::DriverClient kDriverClient;
        auto driverHandle = kDriverClient.open();
        return driverHandle.isValid();
    }

    bool confirmR0OrWarn(bool* const driverReadyOut)
    {
        if (driverReadyOut == nullptr)
        {
            return false;
        }
        *driverReadyOut = isDriverReady();
        if (*driverReadyOut)
        {
            return true;
        }

        const int kRetryResult = ::MessageBoxW(
            nullptr,
            L"KSword R0 驱动当前不可用。\n\n"
            L"请回到 KSword 启用 R0 模式并加载驱动，然后点击“重试”。",
            kPluginTitle,
            MB_RETRYCANCEL | MB_ICONWARNING | MB_SETFOREGROUND);
        if (kRetryResult != IDRETRY)
        {
            return false;
        }

        *driverReadyOut = isDriverReady();
        if (*driverReadyOut)
        {
            return true;
        }
        const int kWarningResult = ::MessageBoxW(
            nullptr,
            L"R0 模式未启用，Cheat Engine 的进程交互无法保证通过 "
            L"KSword 驱动，请小心使用。\n\n是否仍要继续启动？",
            kPluginTitle,
            MB_OKCANCEL | MB_ICONWARNING | MB_DEFBUTTON2 | MB_SETFOREGROUND);
        return kWarningResult == IDOK;
    }

    std::wstring makeStatusPath()
    {
        std::vector<wchar_t> tempPath(MAX_PATH + 1U, L'\0');
        const DWORD kLength = ::GetTempPathW(
            static_cast<DWORD>(tempPath.size()),
            tempPath.data());
        if (kLength == 0U ||
            kLength >= static_cast<DWORD>(tempPath.size()))
        {
            return {};
        }
        return std::wstring(tempPath.data(), kLength) +
            L"ksword-ce-bridge-" +
            std::to_wstring(::GetCurrentProcessId()) +
            L".status";
    }

    std::string readStatusFile(const std::wstring& path)
    {
        std::ifstream input(path, std::ios::binary);
        if (!input)
        {
            return {};
        }
        std::string status;
        std::getline(input, status);
        return status;
    }

    BridgeStatus waitForBridgeStatus(const std::wstring& statusPath)
    {
        constexpr std::size_t kAttemptCount = 200U;
        for (std::size_t attempt = 0U; attempt < kAttemptCount; ++attempt)
        {
            const std::string kStatus = readStatusFile(statusPath);
            if (kStatus == "ready")
            {
                return BridgeStatus::kReady;
            }
            if (kStatus == "failed")
            {
                return BridgeStatus::kFailed;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        return BridgeStatus::kTimeout;
    }

    BridgeStatus launchCheatEngine(
        const std::wstring& pluginDirectory,
        const DWORD targetProcessId,
        DWORD* const cheatEngineProcessIdOut,
        HANDLE* const cheatEngineProcessHandleOut = nullptr)
    {
        if (cheatEngineProcessIdOut != nullptr)
        {
            *cheatEngineProcessIdOut = 0U;
        }
        if (cheatEngineProcessHandleOut != nullptr)
        {
            *cheatEngineProcessHandleOut = nullptr;
        }
        const std::wstring kCeDirectory =
            joinPath(pluginDirectory, L"payload\\Cheat Engine");
        const std::wstring kCeExecutable =
            joinPath(kCeDirectory, L"cheatengine-x86_64.exe");
        const std::wstring kBridgeDll = joinPath(
            pluginDirectory,
            L"bridge\\x64\\KswordCheatEnginePlugin.dll");
        const std::wstring kStatusPath = makeStatusPath();
        if (::GetFileAttributesW(kCeExecutable.c_str()) == INVALID_FILE_ATTRIBUTES ||
            ::GetFileAttributesW(kBridgeDll.c_str()) == INVALID_FILE_ATTRIBUTES ||
            kStatusPath.empty())
        {
            return BridgeStatus::kLaunchFailed;
        }

        (void)::DeleteFileW(kStatusPath.c_str());
        if (::SetEnvironmentVariableW(
                L"KSWORD_CE_BRIDGE_DLL",
                kBridgeDll.c_str()) == FALSE ||
            ::SetEnvironmentVariableW(
                L"KSWORD_CE_BRIDGE_STATUS_FILE",
                kStatusPath.c_str()) == FALSE ||
            ::SetEnvironmentVariableW(
                L"KSWORD_CE_TARGET_PID",
                std::to_wstring(targetProcessId).c_str()) == FALSE)
        {
            return BridgeStatus::kLaunchFailed;
        }

        std::wstring commandLine = L"\"" + kCeExecutable + L"\"";
        std::vector<wchar_t> mutableCommandLine(
            commandLine.begin(),
            commandLine.end());
        mutableCommandLine.push_back(L'\0');
        STARTUPINFOW startupInfo{};
        startupInfo.cb = sizeof(startupInfo);
        PROCESS_INFORMATION processInformation{};

        const BOOL kCreated = ::CreateProcessW(
            kCeExecutable.c_str(),
            mutableCommandLine.data(),
            nullptr,
            nullptr,
            FALSE,
            0U,
            nullptr,
            kCeDirectory.c_str(),
            &startupInfo,
            &processInformation);
        if (kCreated == FALSE)
        {
            return BridgeStatus::kLaunchFailed;
        }

        if (cheatEngineProcessIdOut != nullptr)
        {
            *cheatEngineProcessIdOut = processInformation.dwProcessId;
        }
        ::CloseHandle(processInformation.hThread);
        if (cheatEngineProcessHandleOut != nullptr)
        {
            *cheatEngineProcessHandleOut = processInformation.hProcess;
        }
        const BridgeStatus kStatus = waitForBridgeStatus(kStatusPath);
        if (cheatEngineProcessHandleOut == nullptr)
        {
            ::CloseHandle(processInformation.hProcess);
        }
        (void)::DeleteFileW(kStatusPath.c_str());
        (void)::DeleteFileW((kStatusPath + L".theme").c_str());
        (void)::DeleteFileW((kStatusPath + L".theme.log").c_str());
        return kStatus;
    }

    struct WindowSearchContext
    {
        DWORD processId = 0U;
        HWND window = nullptr;
        int score = 0;
    };

    BOOL CALLBACK findCheatEngineWindow(
        const HWND window,
        const LPARAM contextValue)
    {
        auto* const kContext =
            reinterpret_cast<WindowSearchContext*>(contextValue);
        if (kContext == nullptr || !::IsWindowVisible(window))
        {
            return TRUE;
        }
        DWORD processId = 0U;
        (void)::GetWindowThreadProcessId(window, &processId);
        if (processId != kContext->processId)
        {
            return TRUE;
        }

        wchar_t className[128] = {};
        wchar_t title[256] = {};
        (void)::GetClassNameW(window, className, _countof(className));
        (void)::GetWindowTextW(window, title, _countof(title));
        int score = 0;
        if (std::wcscmp(className, L"TCustomForm") == 0)
        {
            score += 1000;
        }
        if (std::wcsstr(title, L"KSword CE") != nullptr ||
            std::wcsstr(title, L"Cheat Engine") != nullptr)
        {
            score += 500;
        }
        if ((::GetWindowLongPtrW(window, GWL_STYLE) & WS_CAPTION) != 0)
        {
            score += 10;
        }
        if (score > kContext->score)
        {
            kContext->window = window;
            kContext->score = score;
        }
        return TRUE;
    }

    HWND waitForCheatEngineWindow(const DWORD processId)
    {
        constexpr std::size_t kAttemptCount = 200U;
        for (std::size_t attempt = 0U; attempt < kAttemptCount; ++attempt)
        {
            WindowSearchContext context{};
            context.processId = processId;
            (void)::EnumWindows(
                findCheatEngineWindow,
                reinterpret_cast<LPARAM>(&context));
            if (context.window != nullptr && context.score >= 1500)
            {
                return context.window;
            }
            if (gCheatEngineProcess != nullptr &&
                ::WaitForSingleObject(gCheatEngineProcess, 0U) ==
                    WAIT_OBJECT_0)
            {
                return nullptr;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        return nullptr;
    }

    void resizeCheatEngineWindow(const HWND containerWindow)
    {
        if (!::IsWindow(containerWindow) ||
            !::IsWindow(gCheatEngineWindow))
        {
            return;
        }
        RECT clientRectangle{};
        if (::GetClientRect(containerWindow, &clientRectangle) == FALSE)
        {
            return;
        }
        (void)::MoveWindow(
            gCheatEngineWindow,
            0,
            0,
            (std::max)(1L, clientRectangle.right - clientRectangle.left),
            (std::max)(1L, clientRectangle.bottom - clientRectangle.top),
            TRUE);
    }

    bool attachCheatEngineWindow(
        const HWND containerWindow,
        const HWND cheatEngineWindow)
    {
        if (!::IsWindow(containerWindow) ||
            !::IsWindow(cheatEngineWindow))
        {
            return false;
        }

        ::SetLastError(ERROR_SUCCESS);
        const HWND kPreviousParent =
            ::SetParent(cheatEngineWindow, containerWindow);
        if (kPreviousParent == nullptr &&
            ::GetLastError() != ERROR_SUCCESS)
        {
            return false;
        }

        // Retain only CE's client area within the TAB. Remove the title bar and all window edges without
        // replacing CE's own controls or message handling to avoid re-breaking Lazarus's focus state.
        LONG_PTR style = ::GetWindowLongPtrW(cheatEngineWindow, GWL_STYLE);
        style &= ~static_cast<LONG_PTR>(
            WS_POPUP |
            WS_CAPTION |
            WS_THICKFRAME |
            WS_SYSMENU |
            WS_MINIMIZEBOX |
            WS_MAXIMIZEBOX);
        style |= WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN | WS_CLIPSIBLINGS;
        (void)::SetWindowLongPtrW(
            cheatEngineWindow,
            GWL_STYLE,
            style);

        LONG_PTR extendedStyle =
            ::GetWindowLongPtrW(cheatEngineWindow, GWL_EXSTYLE);
        extendedStyle &= ~static_cast<LONG_PTR>(
            WS_EX_APPWINDOW |
            WS_EX_DLGMODALFRAME |
            WS_EX_WINDOWEDGE |
            WS_EX_CLIENTEDGE |
            WS_EX_STATICEDGE);
        extendedStyle |= WS_EX_CONTROLPARENT;
        (void)::SetWindowLongPtrW(
            cheatEngineWindow,
            GWL_EXSTYLE,
            extendedStyle);
        (void)::SetWindowPos(
            cheatEngineWindow,
            HWND_TOP,
            0,
            0,
            0,
            0,
            SWP_NOACTIVATE | SWP_NOMOVE | SWP_NOSIZE |
                SWP_FRAMECHANGED | SWP_SHOWWINDOW);
        gCheatEngineWindow = cheatEngineWindow;
        resizeCheatEngineWindow(containerWindow);
        return true;
    }

    void closeCheatEngine()
    {
        if (::IsWindow(gCheatEngineWindow))
        {
            (void)::PostMessageW(gCheatEngineWindow, WM_CLOSE, 0U, 0);
        }
        gCheatEngineWindow = nullptr;
        if (gCheatEngineProcess != nullptr)
        {
            ::CloseHandle(gCheatEngineProcess);
            gCheatEngineProcess = nullptr;
        }
    }

    void failTab(
        const HWND window,
        const char* const code,
        const char* const message)
    {
        emitError(code, message);
        gTabExitCode = 2;
        if (::IsWindow(window))
        {
            (void)::DestroyWindow(window);
        }
    }

    LRESULT CALLBACK tabWindowProcedure(
        const HWND window,
        const UINT message,
        const WPARAM wParam,
        const LPARAM lParam)
    {
        switch (message)
        {
        case WM_SIZE:
            resizeCheatEngineWindow(window);
            return 0;
        case WM_SETFOCUS:
            if (::IsWindow(gCheatEngineWindow))
            {
                (void)::SetFocus(gCheatEngineWindow);
            }
            return 0;
        case kInitializeTabMessage:
        {
            bool driverReady = false;
            if (!confirmR0OrWarn(&driverReady))
            {
                failTab(
                    window,
                    "r0_required",
                    "Enable KSword R0 mode and load the driver before launching.");
                return 0;
            }

            DWORD cheatEngineProcessId = 0U;
            const BridgeStatus kBridgeStatus = launchCheatEngine(
                parentDirectory(currentExecutablePath()),
                0U,
                &cheatEngineProcessId,
                &gCheatEngineProcess);
            if (kBridgeStatus == BridgeStatus::kLaunchFailed)
            {
                failTab(
                    window,
                    "launch_failed",
                    "The bundled Cheat Engine payload is incomplete or failed to start.");
                return 0;
            }
            if (kBridgeStatus != BridgeStatus::kReady)
            {
                (void)::MessageBoxW(
                    window,
                    L"R0 模式未启用或 KSword 桥接初始化失败，进程交互无法保证"
                    L"通过 KSword 驱动，请小心使用。",
                    kPluginTitle,
                    MB_OK | MB_ICONWARNING | MB_SETFOREGROUND);
                emitJsonLine(
                    "warning",
                    "\"code\":\"bridge_not_ready\","
                    "\"message\":\"R0 mode is not enabled; use carefully.\"");
            }

            const HWND kCheatEngineWindow =
                waitForCheatEngineWindow(cheatEngineProcessId);
            if (kCheatEngineWindow == nullptr ||
                !attachCheatEngineWindow(window, kCheatEngineWindow))
            {
                failTab(
                    window,
                    "embed_failed",
                    "Cheat Engine started but its main window could not be attached.");
                return 0;
            }

            emitJsonLine(
                "tab_embedded",
                "\"cheat_engine_pid\":" +
                    std::to_string(cheatEngineProcessId) +
                    ",\"r0_ready\":" +
                    (driverReady ? "true" : "false") +
                    ",\"bridge_ready\":" +
                    (kBridgeStatus == BridgeStatus::kReady ? "true" : "false"));
            (void)::SetTimer(window, kLifecycleTimerId, 1000U, nullptr);
            return 0;
        }
        case WM_TIMER:
            if (wParam == kLifecycleTimerId)
            {
                HANDLE hostProcess = ::OpenProcess(
                    SYNCHRONIZE,
                    FALSE,
                    gHostProcessId);
                const bool kHostExited =
                    hostProcess == nullptr ||
                    ::WaitForSingleObject(hostProcess, 0U) == WAIT_OBJECT_0;
                if (hostProcess != nullptr)
                {
                    ::CloseHandle(hostProcess);
                }
                const bool kCheatEngineExited =
                    gCheatEngineProcess != nullptr &&
                    ::WaitForSingleObject(
                        gCheatEngineProcess,
                        0U) == WAIT_OBJECT_0;
                if (kHostExited || kCheatEngineExited)
                {
                    gTabExitCode = kHostExited ? 0 : 2;
                    (void)::DestroyWindow(window);
                }
            }
            return 0;
        case WM_DESTROY:
            (void)::KillTimer(window, kLifecycleTimerId);
            closeCheatEngine();
            gTabWindow = nullptr;
            ::PostQuitMessage(gTabExitCode);
            return 0;
        default:
            return ::DefWindowProcW(window, message, wParam, lParam);
        }
    }

    int runTab(const ParsedArguments& arguments)
    {
        WNDCLASSEXW windowClass{};
        windowClass.cbSize = sizeof(windowClass);
        windowClass.lpfnWndProc = tabWindowProcedure;
        windowClass.hInstance = ::GetModuleHandleW(nullptr);
        windowClass.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
        windowClass.hbrBackground =
            reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
        windowClass.lpszClassName = kTabWindowClass;
        if (::RegisterClassExW(&windowClass) == 0U &&
            ::GetLastError() != ERROR_CLASS_ALREADY_EXISTS)
        {
            emitError(
                "window_class_failed",
                "The Cheat Engine Tab window class could not be registered.");
            return 2;
        }

        gHostProcessId = arguments.hostProcessId;
        gTabExitCode = 0;
        gTabWindow = ::CreateWindowExW(
            WS_EX_CONTROLPARENT,
            kTabWindowClass,
            kPluginTitle,
            WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN | WS_CLIPSIBLINGS,
            0,
            0,
            1,
            1,
            arguments.parentWindow,
            nullptr,
            ::GetModuleHandleW(nullptr),
            nullptr);
        if (gTabWindow == nullptr)
        {
            emitError(
                "tab_window_failed",
                "The Cheat Engine Tab child window could not be created.");
            return 2;
        }

        emitJsonLine(
            "tab_ready",
            "\"hwnd\":\"" +
                std::to_string(
                    reinterpret_cast<std::uintptr_t>(gTabWindow)) +
                "\"");
        (void)::PostMessageW(
            gTabWindow,
            kInitializeTabMessage,
            0U,
            0);

        MSG message{};
        while (::GetMessageW(&message, nullptr, 0U, 0U) > 0)
        {
            ::TranslateMessage(&message);
            ::DispatchMessageW(&message);
        }
        return gTabExitCode;
    }

    int runInfo()
    {
        emitJsonLine(
            "info",
            "\"runtime\":\"executable\",\"plugin_type\":\"hybrid\","
            "\"targets\":[\"process\",\"tab\"],"
            "\"commands\":[\"launch\",\"tab\",\"check\",\"info\"],"
            "\"presentation\":\"standalone_or_native_tab\","
            "\"driver_transport\":\"KswordARK\",\"bridge_api\":6");
        return 0;
    }

    int runDriverCheck()
    {
        const bool kReady = isDriverReady();
        emitJsonLine(
            "driver_status",
            std::string("\"r0_ready\":") + (kReady ? "true" : "false"));
        return kReady ? 0 : 2;
    }
}

int wmain(const int argc, wchar_t* const argv[])
{
    const ParsedArguments kArguments = parseArguments(argc, argv);
    if (!kArguments.valid)
    {
        emitError("invalid_arguments", "Invalid KSword plugin arguments.");
        return 64;
    }
    if (kArguments.command == L"info")
    {
        return runInfo();
    }
    if (kArguments.command == L"check")
    {
        return runDriverCheck();
    }
    if (kArguments.command == L"tab")
    {
        return runTab(kArguments);
    }

    emitJsonLine(
        "launch_started",
        "\"target_pid\":" + std::to_string(kArguments.targetProcessId));
    bool driverReady = false;
    if (!confirmR0OrWarn(&driverReady))
    {
        emitError(
            "r0_required",
            "Enable KSword R0 mode and load the driver before launching.");
        return 2;
    }

    const std::wstring kPluginDirectory =
        parentDirectory(currentExecutablePath());
    DWORD cheatEngineProcessId = 0U;
    const BridgeStatus kBridgeStatus = launchCheatEngine(
        kPluginDirectory,
        kArguments.targetProcessId,
        &cheatEngineProcessId);
    if (kBridgeStatus == BridgeStatus::kLaunchFailed)
    {
        ::MessageBoxW(
            nullptr,
            L"Cheat Engine 插件载荷不完整或无法启动，请重新生成插件文件。",
            kPluginTitle,
            MB_OK | MB_ICONERROR | MB_SETFOREGROUND);
        emitError(
            "launch_failed",
            "The bundled Cheat Engine payload is incomplete or failed to start.");
        return 2;
    }
    if (kBridgeStatus != BridgeStatus::kReady)
    {
        ::MessageBoxW(
            nullptr,
            L"R0 模式未启用或 KSword 桥接初始化失败，进程交互无法保证"
            L"通过 KSword 驱动，请小心使用。",
            kPluginTitle,
            MB_OK | MB_ICONWARNING | MB_SETFOREGROUND);
        emitJsonLine(
            "warning",
            "\"code\":\"bridge_not_ready\","
            "\"message\":\"R0 mode is not enabled; use carefully.\"");
    }

    emitJsonLine(
        "launch_complete",
        "\"target_pid\":" + std::to_string(kArguments.targetProcessId) +
        ",\"cheat_engine_pid\":" + std::to_string(cheatEngineProcessId) +
        ",\"r0_ready\":" + (driverReady ? "true" : "false") +
        ",\"bridge_ready\":" +
        (kBridgeStatus == BridgeStatus::kReady ? "true" : "false"));
    return 0;
}

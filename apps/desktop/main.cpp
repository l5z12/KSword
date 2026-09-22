#include "MainWindow.h"

#include <QtCore/QByteArray>
#include <QtCore/QCoreApplication>
#include <QtCore/QEvent>
#include <QtCore/QObject>
#include <QtCore/QStringList>
#include <QtCore/QTimer>
#include <QtGui/QFont>
#include <QtWidgets/QMessageBox>
#include <QtWidgets/QApplication>
#include <QtWidgets/QWidget>

#include "Framework.h"
#include "ui/ThemedMessageBox.h"
#include "ui/GlobalDialogTheme.h"
#include "ui/GlobalRefreshShortcut.h"
#include "ui/WindowChrome.h"
#include "ui/TableColumnAutoFit.h"
#include "ui/TableInteractionSupport.h"
#include "ui/SmoothScrollSupport.h"
#include "ui/TextSearchReplaceSupport.h"
#include "internationalization/LanguageManager.h"
#include "../../shared/crash/WinCrashHandler.h"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <CommCtrl.h>
#include <shellapi.h>

#include <algorithm>
#include <cstdio>
#include <cmath>
#include <cwctype>
#include <fstream>
#include <iostream>
#include <vector>
#include <string>

#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "Comctl32.lib")

namespace
{
    constexpr wchar_t kUnlockerKeyName[] = L"Ksword.FileUnlocker";
    constexpr wchar_t kKswordMainWindowPropertyName[] = L"KswordARK.MainWindow.Singleton.Release";
    constexpr wchar_t kPrivilegeRestartArgument[] = L"--ksword-privilege-restart";
    constexpr ULONG_PTR kUnlockerCopyDataMessageId = 0x4B535755; // "KSWU"：Ksword shell unlocker IPC。
    constexpr DWORD kRestartPredecessorWaitTimeoutMs = 35000;

    // disableQtPopupScrollEffects:
    // - Disable Qt's built-in menu/combobox scroll animations to prevent creation of temporary QRollEffect windows;
    // - The timer at this path previously dereferenced a corrupted child object pointer in QWidgetPrivate::showChildren, causing a crash;
    // - Preserve fade-in/out and application-specific animations without expanding the scope of visual behavior changes.
    void disableQtPopupScrollEffects()
    {
        QApplication::setEffectEnabled(Qt::UI_AnimateMenu, false);
        QApplication::setEffectEnabled(Qt::UI_AnimateCombo, false);
    }

    // localizedStartupText:
    // - Allow the native first-launch dialog, startup screen, and Qt startup popups to share the LanguageManager.
    // - Language packs discovered earlier can be used even before QApplication creation.
    QString localizedStartupText(const QString& textKey, const QString& fallbackText)
    {
        return ks::i18n::contextText(textKey, fallbackText);
    }

    // updateStartupSplash purpose: Update native startup screen based on current effective language.
    void updateStartupSplash(
        const bool splashReady,
        const int progressPercent,
        const QString& textKey,
        const QString& fallbackText)
    {
        if (!splashReady)
        {
            return;
        }
        kSplash.progress(
            localizedStartupText(textKey, fallbackText).toUtf8().toStdString(),
            progressPercent);
    }

    // kStartupScaleRecommendedLogicalWidth:
    // - Defines the minimum recommended logical width for startup resolution checks.
    // - Only pops up the scale recommendation dialog when below this width.
    constexpr int kStartupScaleRecommendedLogicalWidth = 1920;

    // queryCurrentDirectoryPath:
    // - Read the current working directory directly before creating the QApplication instance;
    // - Used to confirm whether the working directory matches expectations when double-clicking to launch during tracing.
    // Returns: Absolute path of the current working directory; returns an empty string on failure.
    std::wstring queryCurrentDirectoryPath()
    {
        std::vector<wchar_t> directoryBuffer(1024, L'\0');
        while (directoryBuffer.size() < 32768)
        {
            const DWORD kCopiedLength = ::GetCurrentDirectoryW(
                static_cast<DWORD>(directoryBuffer.size()),
                directoryBuffer.data());
            if (kCopiedLength == 0)
            {
                return std::wstring();
            }
            if (kCopiedLength < directoryBuffer.size())
            {
                return std::wstring(directoryBuffer.data(), kCopiedLength);
            }
            directoryBuffer.resize(static_cast<std::size_t>(kCopiedLength) + 1, L'\0');
        }
        return std::wstring();
    }

    // ExistingKswordWindowSearchContext:
    // - Input: Read/written by EnumWindows callback;
    // - Processing logic: Record the current process PID and match the Ksword main window marker among top-level visible windows of other processes;
    // - Return behavior: foundWindow being non-null indicates a running instance was found.
    struct ExistingKswordWindowSearchContext
    {
        DWORD currentProcessId = 0; // currentProcessId: PID of the currently launched instance, used to exclude its own window.
        HWND foundWindow = nullptr; // foundWindow: Handle to the existing Ksword main window found.
    };

    // enumExistingKswordWindowProc:
    // - Input: Win32 top-level window enumeration callback parameter;
    // - Processing: Skip windows that are not visible or belong to the current process; identify the Ksword main window only by its window properties;
    // - Note: No longer fall back to window titles to avoid misjudging single-instance status due to title collisions with common windows like resource managers.
    // - Returns: TRUE to continue enumeration; FALSE to stop enumeration after finding the target.
    BOOL CALLBACK enumExistingKswordWindowProc(HWND windowHandle, LPARAM parameter)
    {
        auto* context = reinterpret_cast<ExistingKswordWindowSearchContext*>(parameter);
        if (context == nullptr || windowHandle == nullptr || ::IsWindow(windowHandle) == FALSE)
        {
            return TRUE;
        }
        if (::IsWindowVisible(windowHandle) == FALSE)
        {
            return TRUE;
        }

        DWORD processId = 0;
        (void)::GetWindowThreadProcessId(windowHandle, &processId);
        if (processId == 0 || processId == context->currentProcessId)
        {
            return TRUE;
        }

        if (::GetPropW(windowHandle, kKswordMainWindowPropertyName) != nullptr)
        {
            context->foundWindow = windowHandle;
            return FALSE;
        }
        return TRUE;
    }

    // findExistingKswordMainWindow:
    // - Inputs: None;
    // - Processing: Enumerates system top-level windows before QApplication creation to find an existing Ksword main window.
    // - Returns: HWND if found, otherwise nullptr.
    HWND findExistingKswordMainWindow()
    {
        ExistingKswordWindowSearchContext context;
        context.currentProcessId = ::GetCurrentProcessId();
        (void)::EnumWindows(enumExistingKswordWindowProc, reinterpret_cast<LPARAM>(&context));
        return context.foundWindow;
    }

    // hasCommandLineArgument:
    // - Input argumentText: The internal command-line argument to search for.
    // - Processing: Use CommandLineToArgvW to parse the current command line according to Win32 rules, avoiding manual splitting errors with quotes.
    // - Returns: true if an exact matching argument is found, otherwise false.
    bool hasCommandLineArgument(const wchar_t* argumentText)
    {
        if (argumentText == nullptr || argumentText[0] == L'\0')
        {
            return false;
        }

        int argumentCount = 0;
        LPWSTR* argumentVector = ::CommandLineToArgvW(::GetCommandLineW(), &argumentCount);
        if (argumentVector == nullptr)
        {
            return false;
        }

        bool found = false;
        for (int argumentIndex = 1; argumentIndex < argumentCount; ++argumentIndex)
        {
            if (_wcsicmp(argumentVector[argumentIndex], argumentText) == 0)
            {
                found = true;
                break;
            }
        }
        ::LocalFree(argumentVector);
        return found;
    }

    // collectUnlockPathsFromCommandLine：
    // - Input: None; directly parses the current process command line;
    // - Processing: Collect all '--unlock <path>' arguments for reuse in single-instance forwarding and normal startup flows.
    // - Returns: List of paths to unlock, ordered by command line.
    std::vector<std::wstring> collectUnlockPathsFromCommandLine()
    {
        std::vector<std::wstring> unlockPathList;
        int argumentCount = 0;
        LPWSTR* argumentVector = ::CommandLineToArgvW(::GetCommandLineW(), &argumentCount);
        if (argumentVector == nullptr)
        {
            return unlockPathList;
        }

        for (int argumentIndex = 1; argumentIndex < argumentCount; ++argumentIndex)
        {
            if (_wcsicmp(argumentVector[argumentIndex], L"--unlock") != 0)
            {
                continue;
            }
            if ((argumentIndex + 1) >= argumentCount)
            {
                break;
            }

            const wchar_t* const kPathText = argumentVector[argumentIndex + 1];
            if (kPathText != nullptr && kPathText[0] != L'\0')
            {
                unlockPathList.emplace_back(kPathText);
            }
            argumentIndex += 1;
        }

        ::LocalFree(argumentVector);
        return unlockPathList;
    }

    // sendUnlockPathToExistingMainWindow：
    // - Input: windowHandle is the handle of the existing Ksword main window; unlockPath is the path passed via Shell right-click;
    // - Processing: Pass the path to the existing instance via WM_COPYDATA, which then executes the file unlocker;
    // - Returns: true if the message was successfully delivered; false otherwise.
    bool sendUnlockPathToExistingMainWindow(HWND windowHandle, const std::wstring& unlockPath)
    {
        if (windowHandle == nullptr || ::IsWindow(windowHandle) == FALSE || unlockPath.empty())
        {
            return false;
        }

        COPYDATASTRUCT copyData{};
        copyData.dwData = kUnlockerCopyDataMessageId;
        copyData.cbData = static_cast<DWORD>((unlockPath.size() + 1) * sizeof(wchar_t));
        copyData.lpData = const_cast<wchar_t*>(unlockPath.c_str());

        DWORD_PTR sendResult = 0;
        const LRESULT kMessageResult = ::SendMessageTimeoutW(
            windowHandle,
            WM_COPYDATA,
            0,
            reinterpret_cast<LPARAM>(&copyData),
            SMTO_ABORTIFHUNG | SMTO_BLOCK,
            3000,
            &sendResult);
        return kMessageResult != 0;
    }

    // appendInternalArgumentIfMissing:
    // - Input parameterText: existing command-line argument; argumentText: internal argument to append;
    // - Processing: Append the internal marker if missing in the current parameter to avoid repeated stacking during multi-round privilege restarts.
    // - Returns: A parameter string ready for ShellExecuteW/CreateProcessW.
    std::wstring appendInternalArgumentIfMissing(
        const std::wstring& parameterText,
        const wchar_t* argumentText)
    {
        if (argumentText == nullptr || argumentText[0] == L'\0')
        {
            return parameterText;
        }
        if (hasCommandLineArgument(argumentText))
        {
            return parameterText;
        }

        std::wstring resultText = parameterText;
        if (!resultText.empty())
        {
            resultText += L" ";
        }
        resultText += argumentText;
        return resultText;
    }

    // activateExistingKswordMainWindow:
    // - Input: windowHandle; Existing Ksword main window.
    // - Processing: Restore if minimized, then bring to front and activate if possible.
    // - Return: No return value; failure does not block the current instance from exiting.
    void activateExistingKswordMainWindow(HWND windowHandle)
    {
        if (windowHandle == nullptr || ::IsWindow(windowHandle) == FALSE)
        {
            return;
        }
        if (::IsIconic(windowHandle) != FALSE)
        {
            (void)::ShowWindow(windowHandle, SW_RESTORE);
        }
        else
        {
            (void)::ShowWindow(windowHandle, SW_SHOWNORMAL);
        }
        (void)::SetForegroundWindow(windowHandle);
        (void)::BringWindowToTop(windowHandle);
    }

    // buildStartupTraceFilePath:
    // - Selects a stable output file for 'Native Startup Tracing'.
    // - Prefer writing to %TEMP% to ensure logs are retained even if the console exits immediately.
    // Returns: The full path to the trace log file.
    std::wstring buildStartupTraceFilePath()
    {
        wchar_t tempPathBuffer[MAX_PATH] = {};
        const DWORD kTempLength = ::GetTempPathW(MAX_PATH, tempPathBuffer);
        if (kTempLength > 0 && kTempLength < MAX_PATH)
        {
            std::wstring tempDirectory(tempPathBuffer, kTempLength);
            if (!tempDirectory.empty() && tempDirectory.back() != L'\\' && tempDirectory.back() != L'/')
            {
                tempDirectory.push_back(L'\\');
            }
            return tempDirectory + L"Ksword5.1-startup-trace.log";
        }

        const std::wstring kCurrentDirectory = queryCurrentDirectoryPath();
        if (!kCurrentDirectory.empty())
        {
            return kCurrentDirectory + L"\\Ksword5.1-startup-trace.log";
        }
        return L"Ksword5.1-startup-trace.log";
    }

    // appendStartupTraceFile:
    // - Append native startup trace text to the file;
    // - Avoid losing critical diagnostic information when the console window flashes and exits.
    // Input traceLineText: a complete line of trace text (UTF-8) already including a newline.
    void appendStartupTraceFile(const std::string& traceLineText)
    {
        const std::wstring kTraceFilePath = buildStartupTraceFilePath();
        FILE* traceFileHandle = nullptr;
        if (_wfopen_s(&traceFileHandle, kTraceFilePath.c_str(), L"ab") != 0 || traceFileHandle == nullptr)
        {
            return;
        }

        std::fwrite(traceLineText.data(), 1, traceLineText.size(), traceFileHandle);
        std::fclose(traceFileHandle);
    }

    // startupTraceRaw:
    // - Provide a 'native startup trace' bypass outside kLog.
    // - Simultaneously write to console, OutputDebugStringA, and a temporary file;
    // - Used to locate the issue where 'main exits early before kLog has a chance to display'.
    // Input traceText: Single-line trace text (no newlines).
    void startupTraceRaw(const std::string& traceText)
    {
        SYSTEMTIME localTime = {};
        ::GetLocalTime(&localTime);

        char timePrefixBuffer[64] = {};
        std::snprintf(
            timePrefixBuffer,
            sizeof(timePrefixBuffer),
            "[trace][%04u-%02u-%02u %02u:%02u:%02u.%03u] ",
            static_cast<unsigned int>(localTime.wYear),
            static_cast<unsigned int>(localTime.wMonth),
            static_cast<unsigned int>(localTime.wDay),
            static_cast<unsigned int>(localTime.wHour),
            static_cast<unsigned int>(localTime.wMinute),
            static_cast<unsigned int>(localTime.wSecond),
            static_cast<unsigned int>(localTime.wMilliseconds));

        std::string fullTraceLine = std::string(timePrefixBuffer) + traceText + "\r\n";
        appendStartupTraceFile(fullTraceLine);
        ::OutputDebugStringA(fullTraceLine.c_str());

    }

    // queryCurrentExecutablePath:
    // - Dynamically retrieve the absolute path of the current process executable.
    // - Compatible with long paths to avoid truncation by fixed MAX_PATH buffers.
    // Returns: Non-empty absolute path on success; returns an empty string on failure.
    std::wstring queryCurrentExecutablePath()
    {
        std::vector<wchar_t> pathBuffer(1024, L'\0');
        while (pathBuffer.size() < 32768)
        {
            ::SetLastError(ERROR_SUCCESS);
            const DWORD kCopiedLength = ::GetModuleFileNameW(
                nullptr,
                pathBuffer.data(),
                static_cast<DWORD>(pathBuffer.size()));
            const DWORD kLastError = ::GetLastError();
            if (kCopiedLength == 0)
            {
                return std::wstring();
            }

            if (kCopiedLength > 0
                && kCopiedLength < pathBuffer.size()
                && kLastError != ERROR_INSUFFICIENT_BUFFER)
            {
                return std::wstring(pathBuffer.data(), kCopiedLength);
            }

            pathBuffer.resize(pathBuffer.size() * 2, L'\0');
        }
        return std::wstring();
    }

    // resolveExecutableDirectoryPath:
    // - Parse working directory from the full executable path.
    // - Explicitly pass the directory to CreateProcess to avoid current directory drift after an automatic restart.
    // Input executablePath: absolute path of the current executable.
    // Returns: the directory containing the executable; returns an empty string if resolution fails.
    std::wstring resolveExecutableDirectoryPath(const std::wstring& executablePath)
    {
        const std::size_t kSlashPosition = executablePath.find_last_of(L"\\/");
        if (kSlashPosition == std::wstring::npos)
        {
            return std::wstring();
        }
        return executablePath.substr(0, kSlashPosition);
    }

    bool writeRegistryString(
        HKEY rootKey,
        const std::wstring& subKeyPath,
        const wchar_t* valueName,
        const std::wstring& valueText)
    {
        HKEY keyHandle = nullptr;
        const LONG kCreateResult = ::RegCreateKeyExW(
            rootKey,
            subKeyPath.c_str(),
            0,
            nullptr,
            REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE,
            nullptr,
            &keyHandle,
            nullptr);
        if (kCreateResult != ERROR_SUCCESS)
        {
            return false;
        }

        const DWORD kValueSizeBytes = static_cast<DWORD>((valueText.size() + 1) * sizeof(wchar_t));
        const LONG kSetResult = ::RegSetValueExW(
            keyHandle,
            valueName,
            0,
            REG_SZ,
            reinterpret_cast<const BYTE*>(valueText.c_str()),
            kValueSizeBytes);
        ::RegCloseKey(keyHandle);
        return kSetResult == ERROR_SUCCESS;
    }

    void deleteRegistryTreeBestEffort(HKEY rootKey, const std::wstring& subKeyPath)
    {
        ::RegDeleteTreeW(rootKey, subKeyPath.c_str());
    }

    bool registerUnlockerContextMenu(const std::wstring& executablePath)
    {
        const std::wstring kCommandForFile = L"\"" + executablePath + L"\" --unlock \"%1\"";

        const std::wstring kBaseStar = L"Software\\Classes\\*\\shell\\" + std::wstring(kUnlockerKeyName);
        const std::wstring kBaseDirectory = L"Software\\Classes\\Directory\\shell\\" + std::wstring(kUnlockerKeyName);
        const std::wstring kBaseDrive = L"Software\\Classes\\Drive\\shell\\" + std::wstring(kUnlockerKeyName);
        const std::wstring kMenuText = ks::i18n::contextText(
            QStringLiteral("main.unlocker.menu"),
            QStringLiteral("使用 Ksword 文件解锁器(R3/R0)")).toStdWString();

        // The unlocker is only meaningful for 'selected files/folders/drives', so Directory\Background registration is no longer performed:
        // This location corresponds to the right-click context menu on the desktop and folder backgrounds when no target is selected; the menu items are purely noise.
        // The old version wrote this key; clear it during registration to prevent it from lingering on the desktop right-click menu after an upgrade.
        deleteRegistryTreeBestEffort(
            HKEY_CURRENT_USER,
            L"Software\\Classes\\Directory\\Background\\shell\\" + std::wstring(kUnlockerKeyName));

        const bool kStarOk =
            writeRegistryString(HKEY_CURRENT_USER, kBaseStar, nullptr, kMenuText.c_str())
            && writeRegistryString(HKEY_CURRENT_USER, kBaseStar, L"Icon", executablePath)
            && writeRegistryString(HKEY_CURRENT_USER, kBaseStar + L"\\command", nullptr, kCommandForFile);
        const bool kDirectoryOk =
            writeRegistryString(HKEY_CURRENT_USER, kBaseDirectory, nullptr, kMenuText.c_str())
            && writeRegistryString(HKEY_CURRENT_USER, kBaseDirectory, L"Icon", executablePath)
            && writeRegistryString(HKEY_CURRENT_USER, kBaseDirectory + L"\\command", nullptr, kCommandForFile);
        const bool kDriveOk =
            writeRegistryString(HKEY_CURRENT_USER, kBaseDrive, nullptr, kMenuText.c_str())
            && writeRegistryString(HKEY_CURRENT_USER, kBaseDrive, L"Icon", executablePath)
            && writeRegistryString(HKEY_CURRENT_USER, kBaseDrive + L"\\command", nullptr, kCommandForFile);

        return kStarOk && kDirectoryOk && kDriveOk;
    }

    void unregisterUnlockerContextMenu()
    {
        deleteRegistryTreeBestEffort(
            HKEY_CURRENT_USER,
            L"Software\\Classes\\*\\shell\\" + std::wstring(kUnlockerKeyName));
        deleteRegistryTreeBestEffort(
            HKEY_CURRENT_USER,
            L"Software\\Classes\\Directory\\shell\\" + std::wstring(kUnlockerKeyName));
        deleteRegistryTreeBestEffort(
            HKEY_CURRENT_USER,
            L"Software\\Classes\\Drive\\shell\\" + std::wstring(kUnlockerKeyName));
        // Directory\Background is no longer registered, but must still be deleted: users with old versions installed need to be fully cleaned up.
        deleteRegistryTreeBestEffort(
            HKEY_CURRENT_USER,
            L"Software\\Classes\\Directory\\Background\\shell\\" + std::wstring(kUnlockerKeyName));
    }

    // kNativeAppIconResourceName:
    // - Points to the main icon resource name declared in AppIcon.rc;
    // - Synchronizes the native icon to the Qt main window title bar and taskbar.
    constexpr wchar_t kNativeAppIconResourceName[] = L"IDI_APP_ICON";

    // isCurrentProcessElevated:
    // - Check if the current process is running with administrator privileges.
    // - Purpose: Reused for the logic to automatically request administrator privileges at startup.
    // Returns: true if elevated; false if standard permissions.
    bool isCurrentProcessElevated()
    {
        HANDLE tokenHandle = nullptr;
        if (::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &tokenHandle) == FALSE)
        {
            return false;
        }

        // tokenElevation: Holds the result of the TokenElevation query.
        TOKEN_ELEVATION tokenElevation{};
        DWORD returnLength = 0;
        const BOOL kQueryOk = ::GetTokenInformation(
            tokenHandle,
            TokenElevation,
            &tokenElevation,
            sizeof(tokenElevation),
            &returnLength);
        ::CloseHandle(tokenHandle);
        return kQueryOk != FALSE && tokenElevation.TokenIsElevated != 0;
    }

    // tryEnableStartupProcessPrivileges：
    // - Input: None; directly operates on the current process token;
    // - Processing: Enable process-related privileges one by one after admin launch, overriding common system privileges in lines 30-52 of the permissions page.
    // - Returns: true if at least one target privilege was successfully enabled; false if the current process is not elevated, the token handle failed to open, or all attempts failed.
    bool tryEnableStartupProcessPrivileges()
    {
        if (!isCurrentProcessElevated())
        {
            startupTraceRaw("startup process privileges skipped: process is not elevated");
            KLogEvent event;
            warn << event
                << "[main] 启动期进程权限批量申请跳过：当前进程不是管理员。"
                << eol;
            return false;
        }

        HANDLE tokenHandle = nullptr;
        if (::OpenProcessToken(
            ::GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &tokenHandle) == FALSE)
        {
            const DWORD kErrorCode = ::GetLastError();
            startupTraceRaw(
                std::string("startup process privileges OpenProcessToken failed, error=")
                + std::to_string(kErrorCode));
            KLogEvent event;
            err << event
                << "[main] 启动期进程权限批量申请失败：OpenProcessToken error="
                << kErrorCode
                << eol;
            return false;
        }

        int enabledCount = 0;
        int notAssignedCount = 0;
        int failedCount = 0;
        std::string failedDetailText;

        for (const std::string& privilegeNameText : ks::process::knownTokenPrivilegeNames())
        {
            const std::wstring kPrivilegeName(privilegeNameText.begin(), privilegeNameText.end());
            LUID privilegeLuid{};
            if (::LookupPrivilegeValueW(nullptr, kPrivilegeName.c_str(), &privilegeLuid) == FALSE)
            {
                const DWORD kErrorCode = ::GetLastError();
                ++failedCount;
                failedDetailText += privilegeNameText + ":LookupPrivilegeValue=" + std::to_string(kErrorCode) + ";";
                continue;
            }

            TOKEN_PRIVILEGES tokenPrivileges{};
            tokenPrivileges.PrivilegeCount = 1;
            tokenPrivileges.Privileges[0].Luid = privilegeLuid;
            tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            ::SetLastError(ERROR_SUCCESS);
            if (::AdjustTokenPrivileges(
                tokenHandle,
                FALSE,
                &tokenPrivileges,
                sizeof(tokenPrivileges),
                nullptr,
                nullptr) == FALSE)
            {
                const DWORD kErrorCode = ::GetLastError();
                ++failedCount;
                failedDetailText += privilegeNameText + ":AdjustTokenPrivileges=" + std::to_string(kErrorCode) + ";";
                continue;
            }

            const DWORD kAdjustError = ::GetLastError();
            if (kAdjustError == ERROR_SUCCESS)
            {
                ++enabledCount;
                continue;
            }

            if (kAdjustError == ERROR_NOT_ALL_ASSIGNED)
            {
                ++notAssignedCount;
            }
            else
            {
                ++failedCount;
            }
            failedDetailText += privilegeNameText + ":AdjustResult=" + std::to_string(kAdjustError) + ";";
        }

        ::CloseHandle(tokenHandle);

        startupTraceRaw(
            std::string("startup process privileges finished: enabled=")
            + std::to_string(enabledCount)
            + ", not_assigned="
            + std::to_string(notAssignedCount)
            + ", failed="
            + std::to_string(failedCount)
            + ", detail="
            + failedDetailText);

        KLogEvent event;
        info << event
            << "[main] 启动期进程权限批量申请完成，enabled="
            << enabledCount
            << ", notAssigned="
            << notAssignedCount
            << ", failed="
            << failedCount
            << eol;

        if (enabledCount <= 0)
        {
            KLogEvent failEvent;
            err << failEvent
                << "[main] 启动期进程权限批量申请没有成功启用任何目标权限。"
                << eol;
            return false;
        }

        return true;
    }

    // extractCurrentProcessParameterText:
    // - Extract parameter text after the 'exe' from the current command line;
    // - runas: pass through unchanged on restart to avoid behavioral differences.
    // Returns: parameter string suitable for passing to ShellExecuteW.
    std::wstring extractCurrentProcessParameterText()
    {
        const wchar_t* commandLineText = ::GetCommandLineW();
        if (commandLineText == nullptr)
        {
            return std::wstring();
        }

        // cursorPointer: Iterate through the command line to locate the start position of the first argument.
        const wchar_t* cursorPointer = commandLineText;
        bool insideQuotes = false;
        while (*cursorPointer != L'\0')
        {
            if (*cursorPointer == L'"')
            {
                insideQuotes = !insideQuotes;
            }
            else if (!insideQuotes && std::iswspace(static_cast<wint_t>(*cursorPointer)) != 0)
            {
                break;
            }
            ++cursorPointer;
        }

        while (std::iswspace(static_cast<wint_t>(*cursorPointer)) != 0)
        {
            ++cursorPointer;
        }

        return std::wstring(cursorPointer);
    }

    // tryLaunchElevatedSelfBeforeSplash:
    // - Attempt to launch an elevated instance via runas before the splash screen appears.
    // - Exit the current normal-privilege instance directly on success to prevent double-launching.
    // Returns: true = elevated instance launched; false = failed, proceed with normal startup.
    bool tryLaunchElevatedSelfBeforeSplash()
    {
        const std::wstring kExecutablePath = queryCurrentExecutablePath();
        if (kExecutablePath.empty())
        {
            return false;
        }

        // parameterText purpose: Stores current command-line arguments to pass to the newly launched instance.
        const std::wstring kParameterText = appendInternalArgumentIfMissing(
            extractCurrentProcessParameterText(),
            kPrivilegeRestartArgument);
        const std::wstring kExecutableDirectory = resolveExecutableDirectoryPath(kExecutablePath);
        HINSTANCE shellResult = ::ShellExecuteW(
            nullptr,
            L"runas",
            kExecutablePath.c_str(),
            kParameterText.empty() ? nullptr : kParameterText.c_str(),
            kExecutableDirectory.empty() ? nullptr : kExecutableDirectory.c_str(),
            SW_SHOWNORMAL);
        return reinterpret_cast<INT_PTR>(shellResult) > 32;
    }

    bool tryLaunchUacDeskCompanion()
    {
        const std::wstring kMainPath = queryCurrentExecutablePath();
        if (kMainPath.empty()) return false;
        const std::wstring kDirectory = resolveExecutableDirectoryPath(kMainPath);
        if (kDirectory.empty()) return false;
        const std::wstring kHelperPath = kDirectory + L"\\KswordUacDesk.exe";
        if (::GetFileAttributesW(kHelperPath.c_str()) == INVALID_FILE_ATTRIBUTES) return false;
        std::wstring commandLine = L"\"" + kHelperPath + L"\"";
        std::vector<wchar_t> mutableCommand(commandLine.begin(), commandLine.end());
        mutableCommand.push_back(L'\0');
        STARTUPINFOW startupInfo{};
        startupInfo.cb = sizeof(startupInfo);
        startupInfo.dwFlags = STARTF_USESHOWWINDOW;
        startupInfo.wShowWindow = SW_HIDE;
        PROCESS_INFORMATION processInformation{};
        const BOOL kCreateOk = ::CreateProcessW(nullptr, mutableCommand.data(), nullptr, nullptr, FALSE,
            CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW, nullptr, kDirectory.c_str(), &startupInfo, &processInformation);
        if (!kCreateOk) return false;
        ::CloseHandle(processInformation.hThread);
        ::CloseHandle(processInformation.hProcess);
        return true;
    }

    // tryCreateRestartedSelfBeforeSplash:
    // - Restart the current executable using CreateProcessW before creating the QApplication.
    // - Only rely on the configuration file to carry scaling results; do not pass scaling state via parameters.
    // - The current process is only responsible for launching the new instance; exit is handled by main based on the return value.
    // Returns: true means the new instance has been launched; false means startup failed, and the caller continues the current startup flow.
    bool tryCreateRestartedSelfBeforeSplash()
    {
        const std::wstring kExecutablePath = queryCurrentExecutablePath();
        if (kExecutablePath.empty())
        {
            return false;
        }

        // commandLineText purpose: CreateProcessW requires a writable command-line buffer.
        std::wstring commandLineText = L"\"" + kExecutablePath + L"\"";
        const std::wstring kParameterText = appendInternalArgumentIfMissing(
            extractCurrentProcessParameterText(),
            kPrivilegeRestartArgument);
        if (!kParameterText.empty())
        {
            commandLineText += L" ";
            commandLineText += kParameterText;
        }

        const std::wstring kExecutableDirectory = resolveExecutableDirectoryPath(kExecutablePath);
        STARTUPINFOW startupInfo = {};
        startupInfo.cb = sizeof(startupInfo);
        startupInfo.dwFlags = STARTF_USESHOWWINDOW;
        startupInfo.wShowWindow = SW_SHOWNORMAL;

        PROCESS_INFORMATION processInformation = {};
        const BOOL kCreateOk = ::CreateProcessW(
            kExecutablePath.c_str(),
            &commandLineText[0],
            nullptr,
            nullptr,
            FALSE,
            0,
            nullptr,
            kExecutableDirectory.empty() ? nullptr : kExecutableDirectory.c_str(),
            &startupInfo,
            &processInformation);
        if (kCreateOk == FALSE)
        {
            return false;
        }

        ::CloseHandle(processInformation.hThread);
        ::CloseHandle(processInformation.hProcess);
        return true;
    }

    // initializeProcessDpiAwareness:
    // - Set process DPI awareness at the earliest stage of the main function;
    // - Ensure stable scaling behavior between the startup page and the Qt main window.
    void initializeProcessDpiAwareness()
    {
        HMODULE user32ModuleHandle = ::GetModuleHandleW(L"user32.dll");
        if (user32ModuleHandle != nullptr)
        {
            using SetDpiAwarenessContextFunction = BOOL(WINAPI*)(DPI_AWARENESS_CONTEXT);
            const SetDpiAwarenessContextFunction kSetContextFunction =
                reinterpret_cast<SetDpiAwarenessContextFunction>(
                    ::GetProcAddress(user32ModuleHandle, "SetProcessDpiAwarenessContext"));
            if (kSetContextFunction != nullptr)
            {
                if (kSetContextFunction(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2))
                {
                    return;
                }
                if (kSetContextFunction(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE))
                {
                    return;
                }
            }
        }

        // Fallback for legacy systems: at least enable system DPI awareness.
        ::SetProcessDPIAware();
    }

    // querySystemScalePercent:
    // - Read the current system scaling percentage (100/125/150...);
    // - Prefer GetDpiForSystem on new systems, fall back to GDI calculation on old systems.
    // Returns: The system scaling percentage (minimum 100).
    int querySystemScalePercent()
    {
        HMODULE user32ModuleHandle = ::GetModuleHandleW(L"user32.dll");
        if (user32ModuleHandle != nullptr)
        {
            using GetDpiForSystemFunction = UINT(WINAPI*)();
            const GetDpiForSystemFunction kGetDpiForSystemFunction =
                reinterpret_cast<GetDpiForSystemFunction>(
                    ::GetProcAddress(user32ModuleHandle, "GetDpiForSystem"));
            if (kGetDpiForSystemFunction != nullptr)
            {
                const UINT kDpiValue = kGetDpiForSystemFunction();
                if (kDpiValue >= 96U)
                {
                    const int kScalePercent = static_cast<int>(
                        std::lround((static_cast<double>(kDpiValue) * 100.0) / 96.0));
                    return std::max(100, kScalePercent);
                }
            }
        }

        HDC screenDeviceContext = ::GetDC(nullptr);
        if (screenDeviceContext == nullptr)
        {
            return 100;
        }
        const int kLogPixelsX = ::GetDeviceCaps(screenDeviceContext, LOGPIXELSX);
        ::ReleaseDC(nullptr, screenDeviceContext);
        if (kLogPixelsX <= 0)
        {
            return 100;
        }
        const int kScalePercent = static_cast<int>(
            std::lround((static_cast<double>(kLogPixelsX) * 100.0) / 96.0));
        return std::max(100, kScalePercent);
    }

    // buildPercentText:
    // - Converts the ratio value to a percentage text string;
    // - Used for the pre-launch recommended scaling popup.
    // Parameter ratioValue: ratio value (1.0 = 100%).
    // Returns: A wide string representing the percentage.
    std::wstring buildPercentText(const double ratioValue)
    {
        const int kPercentValue = static_cast<int>(std::lround(ratioValue * 100.0));
        return std::to_wstring(kPercentValue) + L"%";
    }

    // showStartupScaleRecommendationDialog:
    // - Prompt to apply recommended scaling before the first low-resolution startup;
    // - Provide only two outcomes: 'Apply Recommended Scale' or 'Keep Current Scale'.
    // Input parameter logicalClientWidth: the available width calculated as 'physical pixels / system scale'.
    // Parameter currentScaleFactor: current configured scale factor.
    // Input parameter recommendedScaleFactor: recommended scaling factor.
    // Output parameter applyRecommendedOut: whether to apply the recommended value.
    // Returns: true = dialog displayed successfully; false = dialog call failed.
    bool showStartupScaleRecommendationDialog(
        const int logicalClientWidth,
        const double currentScaleFactor,
        const double recommendedScaleFactor,
        bool* applyRecommendedOut)
    {
        if (applyRecommendedOut == nullptr)
        {
            return false;
        }
        *applyRecommendedOut = false;

        const std::wstring kCurrentScaleText = buildPercentText(currentScaleFactor);
        const std::wstring kRecommendedScaleText = buildPercentText(recommendedScaleFactor);
        const QString kDialogContentSourceTemplate = QStringLiteral(
            "当前可用宽度约 %1px，小于推荐的 %2px。\n"
            "当前缩放：%3\n"
            "推荐缩放：%4\n\n"
            "是否应用推荐缩放？Ksword 将保存设置并立即重启。" );
        const QString kDialogContentText = localizedStartupText(
            QStringLiteral("main.scale.dialog.content"),
            kDialogContentSourceTemplate)
            .arg(logicalClientWidth)
            .arg(kStartupScaleRecommendedLogicalWidth)
            .arg(QString::fromStdWString(kCurrentScaleText))
            .arg(QString::fromStdWString(kRecommendedScaleText));
        const std::wstring kApplyAndRestartText = localizedStartupText(
            QStringLiteral("main.scale.dialog.apply"), QStringLiteral("应用并重启")).toStdWString();
        const std::wstring kKeepCurrentSettingsText = localizedStartupText(
            QStringLiteral("main.scale.dialog.keep"), QStringLiteral("保持当前设置")).toStdWString();
        const std::wstring kDialogContentTextWide = kDialogContentText.toStdWString();
        const std::wstring kDialogTitleText = localizedStartupText(
            QStringLiteral("main.scale.dialog.title"), QStringLiteral("Ksword5.1 启动缩放建议")).toStdWString();
        const std::wstring kMainInstructionText = localizedStartupText(
            QStringLiteral("main.scale.dialog.instruction"), QStringLiteral("检测到当前显示可用宽度偏小")).toStdWString();

        // dialogButtons function: Custom button set for taskDialog.
        TASKDIALOG_BUTTON dialogButtons[] =
        {
            { IDYES, kApplyAndRestartText.c_str() },
            { IDNO, kKeepCurrentSettingsText.c_str() }
        };

        TASKDIALOGCONFIG dialogConfig = {};
        dialogConfig.cbSize = sizeof(dialogConfig);
        dialogConfig.hInstance = ::GetModuleHandleW(nullptr);
        dialogConfig.dwFlags = TDF_ALLOW_DIALOG_CANCELLATION | TDF_POSITION_RELATIVE_TO_WINDOW;
        dialogConfig.pszWindowTitle = kDialogTitleText.c_str();
        dialogConfig.pszMainInstruction = kMainInstructionText.c_str();
        dialogConfig.pszContent = kDialogContentTextWide.c_str();
        dialogConfig.pButtons = dialogButtons;
        dialogConfig.cButtons = ARRAYSIZE(dialogButtons);
        dialogConfig.nDefaultButton = IDYES;

        int pressedButtonId = 0;
        const HRESULT kDialogResult = ::TaskDialogIndirect(
            &dialogConfig,
            &pressedButtonId,
            nullptr,
            nullptr);
        if (FAILED(kDialogResult))
        {
            return false;
        }

        *applyRecommendedOut = (pressedButtonId == IDYES);
        return true;
    }

    // maybeApplyStartupScaleRecommendation:
    // - Only prompt for a recommended scale when no configuration file is detected and the resolution is low;
    // - Write the user's choice directly back to startupSettings, then continue with Qt initialization in the current process.
    // - Best-effort save of the configuration file; do not block main window startup on save failure.
    // Invocation: call before QApplication creation.
    // Input parameter startupSettings: Startup configuration object (updated as needed).
    // Returns: true if the current process is already taken over by another instance and should exit immediately; false to continue the current startup flow.
    bool maybeApplyStartupScaleRecommendation(ks::settings::AppearanceSettings* startupSettings)
    {
        startupTraceRaw("enter maybeApplyStartupScaleRecommendation");
        if (startupSettings == nullptr)
        {
            startupTraceRaw("maybeApplyStartupScaleRecommendation: startupSettings is null");
            return false;
        }

        // scaleDecisionEvent purpose: Chain the startup scaling decision logic logs.
        KLogEvent scaleDecisionEvent;
        if (ks::settings::settingsJsonFileExistsForRead())
        {
            startupTraceRaw("maybeApplyStartupScaleRecommendation: settings file exists, skip first-run prompt");
            info << scaleDecisionEvent
                << "[main] 已检测到配置文件，按配置文件直接启动。"
                << eol;
            return false;
        }

        const int kPhysicalScreenWidth = std::max(1, ::GetSystemMetrics(SM_CXSCREEN));
        const int kSystemScalePercent = querySystemScalePercent();
        const int kLogicalClientWidth = static_cast<int>(
            std::lround((static_cast<double>(kPhysicalScreenWidth) * 100.0) / static_cast<double>(kSystemScalePercent)));
        if (kLogicalClientWidth >= kStartupScaleRecommendedLogicalWidth)
        {
            startupTraceRaw(
                std::string("maybeApplyStartupScaleRecommendation: logical width >= threshold, logicalWidth=")
                + std::to_string(kLogicalClientWidth)
                + ", threshold="
                + std::to_string(kStartupScaleRecommendedLogicalWidth));
            info << scaleDecisionEvent
                << "[main] 可用宽度满足要求，跳过推荐缩放。 logicalWidth="
                << kLogicalClientWidth
                << ", systemScalePercent="
                << kSystemScalePercent
                << eol;
            return false;
        }

        const double kCurrentScaleFactor = ks::settings::normalizeWindowScaleFactor(
            startupSettings->startupWindowScaleFactor);
        const double kRecommendedScaleFactor = ks::settings::normalizeWindowScaleFactor(
            std::min(
                1.0,
                static_cast<double>(kLogicalClientWidth) / static_cast<double>(kStartupScaleRecommendedLogicalWidth)));
        if (kRecommendedScaleFactor >= kCurrentScaleFactor - 0.0001)
        {
            startupTraceRaw(
                std::string("maybeApplyStartupScaleRecommendation: recommended scale not smaller than current, current=")
                + std::to_string(kCurrentScaleFactor)
                + ", recommended="
                + std::to_string(kRecommendedScaleFactor));
            info << scaleDecisionEvent
                << "[main] 当前缩放已不大于推荐值，无需提示。 current="
                << kCurrentScaleFactor
                << ", recommended="
                << kRecommendedScaleFactor
                << eol;
            return false;
        }

        bool applyRecommendedScale = false;
        const bool kPromptHandled = showStartupScaleRecommendationDialog(
            kLogicalClientWidth,
            kCurrentScaleFactor,
            kRecommendedScaleFactor,
            &applyRecommendedScale);
        startupTraceRaw(
            std::string("maybeApplyStartupScaleRecommendation: dialog returned, handled=")
            + (kPromptHandled ? "true" : "false")
            + ", applyRecommendedScale="
            + (applyRecommendedScale ? "true" : "false"));
        if (!kPromptHandled)
        {
            warn << scaleDecisionEvent
                << "[main] 首次启动缩放推荐弹窗调用失败，改为按当前缩放继续启动。"
                << eol;
            return false;
        }

        // Directly update the startup configuration in memory:
        // - "Apply recommended scaling" causes subsequent QT_SCALE_FACTOR usage to adopt the recommended value;
        // - "Keep current settings" retains the current scaling but also persists the startup configuration to disk to avoid repeated pop-ups.
        startupSettings->startupWindowScaleFactor = applyRecommendedScale
            ? kRecommendedScaleFactor
            : kCurrentScaleFactor;
        startupSettings->startupScaleRecommendPromptDisabled = false;

        QString saveErrorText;
        const bool kSaveOk = ks::settings::saveAppearanceSettings(*startupSettings, &saveErrorText);
        startupTraceRaw(
            std::string("maybeApplyStartupScaleRecommendation: saveAppearanceSettings returned ")
            + (kSaveOk ? "true" : "false"));
        if (!kSaveOk)
        {
            // A save failure only affects whether the prompt appears again on the next startup:
            // - Current startup can continue;
            // - Do not prevent the main window from appearing entirely due to configuration file write failure.
            warn << scaleDecisionEvent
                << "[main] 首次启动缩放配置保存失败，本次按内存中的缩放继续启动, error="
                << saveErrorText.toStdString()
                << eol;
            return false;
        }

        info << scaleDecisionEvent
            << "[main] 首次启动缩放配置已写入, logicalWidth="
            << kLogicalClientWidth
            << ", current="
            << kCurrentScaleFactor
            << ", recommended="
            << kRecommendedScaleFactor
            << ", applied="
            << (applyRecommendedScale ? "true" : "false")
            << eol;

        // QApplication has not been created yet when this function runs:
        // - Subsequent main execution will still apply QT_SCALE_FACTOR based on startupSettings;
        // - Therefore, no restart is needed here; simply continue with the current startup chain.
        info << scaleDecisionEvent
            << "[main] 首次启动缩放决策完成，继续当前实例启动。"
            << eol;
        startupTraceRaw("leave maybeApplyStartupScaleRecommendation with false");
        return false;
    }

    // applyQtScaleFactorEnvironment:
    // - Set QT_SCALE_FACTOR before creating QApplication.
    // - This value participates in the entire Qt main window scaling calculation.
    // Input parameter scaleFactor: Target scaling factor (0.50~2.00).
    void applyQtScaleFactorEnvironment(const double scaleFactor)
    {
        const double kNormalizedScaleFactor = ks::settings::normalizeWindowScaleFactor(scaleFactor);
        const QByteArray kScaleFactorText = QByteArray::number(kNormalizedScaleFactor, 'f', 3);
        qputenv("QT_SCALE_FACTOR", kScaleFactorText);

        KLogEvent scaleEnvEvent;
        info << scaleEnvEvent
            << "[main] 已设置 QT_SCALE_FACTOR="
            << kScaleFactorText.toStdString()
            << eol;
    }

    // loadSharedIconFromResource:
    // - Loads a shared icon from executable resources at specified dimensions.
    // - Used by the main window to set taskbar/title bar icons.
    // Input parameters widthValue/heightValue: Target icon dimensions.
    // Returns: an icon handle; nullptr on failure.
    HICON loadSharedIconFromResource(const int widthValue, const int heightValue)
    {
        return reinterpret_cast<HICON>(
            ::LoadImageW(
                ::GetModuleHandleW(nullptr),
                kNativeAppIconResourceName,
                IMAGE_ICON,
                widthValue,
                heightValue,
                LR_DEFAULTCOLOR | LR_SHARED));
    }

    // applyNativeAppIconToWidget:
    // - Explicitly synchronize the AppIcon.rc icon to the Qt top-level window;
    // - Fix the issue where the window icon does not follow the exe icon.
    // Input targetWidget: Target top-level window.
    void applyNativeAppIconToWidget(QWidget* targetWidget)
    {
        if (targetWidget == nullptr)
        {
            return;
        }

        const HWND kTargetWindowHandle = reinterpret_cast<HWND>(targetWidget->winId());
        if (kTargetWindowHandle == nullptr)
        {
            return;
        }

        const int kBigIconWidth = ::GetSystemMetrics(SM_CXICON);
        const int kBigIconHeight = ::GetSystemMetrics(SM_CYICON);
        const int kSmallIconWidth = ::GetSystemMetrics(SM_CXSMICON);
        const int kSmallIconHeight = ::GetSystemMetrics(SM_CYSMICON);

        HICON bigIconHandle = loadSharedIconFromResource(kBigIconWidth, kBigIconHeight);
        HICON smallIconHandle = loadSharedIconFromResource(kSmallIconWidth, kSmallIconHeight);

        if (bigIconHandle != nullptr)
        {
            ::SendMessageW(
                kTargetWindowHandle,
                WM_SETICON,
                static_cast<WPARAM>(ICON_BIG),
                reinterpret_cast<LPARAM>(bigIconHandle));
        }
        if (smallIconHandle != nullptr)
        {
            ::SendMessageW(
                kTargetWindowHandle,
                WM_SETICON,
                static_cast<WPARAM>(ICON_SMALL),
                reinterpret_cast<LPARAM>(smallIconHandle));
            ::SendMessageW(
                kTargetWindowHandle,
                WM_SETICON,
                static_cast<WPARAM>(ICON_SMALL2),
                reinterpret_cast<LPARAM>(smallIconHandle));
        }
    }

    // FirstFrameSplashHider:
    // - Wait for the main window's central background host to receive the first paint.
    // - Queue the hide action after the current Paint completes to prevent the splash screen from disappearing before the background is fully rendered;
    // - Provides a timed fallback to avoid missed detections caused by platform message differences.
    class FirstFrameSplashHider final : public QObject
    {
    public:
        // Constructor purpose:
        // - Stores pointers to the main window and the startup controller;
        // - eventFilter and the timer handle subsequent hiding consistently.
        // Input targetWindow: main window object.
        // Input parameter splashWindow: The splash screen controller object.
        FirstFrameSplashHider(
            MainWindow* targetWindow,
            KStartupSplash* splashWindow)
            : QObject(targetWindow)
            , targetWindow_(targetWindow)
            , targetCentralWidget_(targetWindow != nullptr ? targetWindow->centralWidget() : nullptr)
            , splashWindow_(splashWindow)
        {
            // Startup fallback: if the event chain misses the window becoming visible, force close the startup page after 1.5 seconds.
            QTimer::singleShot(1500, this, [this]()
                {
                    if (hidden_ || targetWindow_ == nullptr)
                    {
                        return;
                    }
                    if (targetWindow_->isVisible() && !targetWindow_->isMinimized())
                    {
                        hideSplashAndDetach();
                    }
                });
        }

    protected:
        // eventFilter:
        // - Hide the startup page after capturing events related to the first frame;
        // - Listen to both the main window and the central widget to avoid missing events due to listening only to the main window.
        bool eventFilter(QObject* watchedObject, QEvent* eventObject) override
        {
            if (hidden_ || eventObject == nullptr || targetWindow_ == nullptr)
            {
                return QObject::eventFilter(watchedObject, eventObject);
            }

            // watchedTargetWindow role: determine if the current event originates from the main window.
            const bool kWatchedTargetWindow = (watchedObject == targetWindow_);
            // watchedTargetCentral purpose: Determine if the current event originates from the central content control.
            const bool kWatchedTargetCentral = (watchedObject == targetCentralWidget_);
            if (!kWatchedTargetWindow && !kWatchedTargetCentral)
            {
                return QObject::eventFilter(watchedObject, eventObject);
            }

            // eventType purpose: Unifies the current event type to facilitate extending the first-frame judgment condition.
            const QEvent::Type kEventType = eventObject->type();
            const bool kIsBackgroundPaint =
                kEventType == QEvent::Paint
                && (kWatchedTargetCentral || (targetCentralWidget_ == nullptr && kWatchedTargetWindow));

            if (!hidden_
                && !hideQueued_
                && kIsBackgroundPaint
                && targetWindow_->isVisible()
                && !targetWindow_->isMinimized())
            {
                hideQueued_ = true;
                QTimer::singleShot(0, this, [this]()
                    {
                        if (hidden_ || targetWindow_ == nullptr)
                        {
                            return;
                        }
                        if (targetWindow_->isVisible() && !targetWindow_->isMinimized())
                        {
                            hideSplashAndDetach();
                            return;
                        }
                        hideQueued_ = false;
                    });
            }
            return QObject::eventFilter(watchedObject, eventObject);
        }

    private:
        // hideSplashAndDetach:
        // - Performs a one-time hide action and removes the event filter;
        // - Ensure the splash screen is hidden only once to avoid duplicate calls.
        void hideSplashAndDetach()
        {
            hidden_ = true;
            // The first frame moment is when the user "sees the main window"; `window.show()` is merely the initiation.
            // The difference between the two is the startup duration segment most easily overlooked.
            startupTraceRaw("first_frame_painted");
            if (splashWindow_ != nullptr)
            {
                splashWindow_->progress("启动完成", 100);
                splashWindow_->hide();
            }
            if (targetWindow_ != nullptr)
            {
                targetWindow_->removeEventFilter(this);
            }
            if (targetCentralWidget_ != nullptr)
            {
                targetCentralWidget_->removeEventFilter(this);
            }

        }

        MainWindow* targetWindow_ = nullptr;     // m_targetWindow: Pointer to the main window object.
        QWidget* targetCentralWidget_ = nullptr; // m_targetCentralWidget: Pointer to the main window's central content widget.
        KStartupSplash* splashWindow_ = nullptr; // m_splashWindow: Pointer to the startup page controller.
        bool hidden_ = false;                    // m_hidden: Whether the hide action has been executed.
        bool hideQueued_ = false;                // m_hideQueued: Whether the hide action has been queued to occur after the first background paint.
    };
}

int main(int argc, char* argv[])
{
    // Startup flow:
    // 1) initialize DPI awareness.
    // 2) Read configuration and handle recommended scaling;
    // 3) Handle automatic privilege escalation according to configuration;
    // 4) Set QT_SCALE_FACTOR;
    // 5) Display the Framework startup page and create the main window.
    ks::crash::Configuration crashConfiguration;
    crashConfiguration.productName = L"KswordARK";
    crashConfiguration.dumpFilePrefix = L"Ksword5.1";
    crashConfiguration.preferLauncherReporter = true;
    ks::crash::installCrashHandler(crashConfiguration);
    const bool kCrashRestartWait =
        ks::crash::waitForCrashRestartTargetFromCommandLine(
            kRestartPredecessorWaitTimeoutMs);
    startupTraceRaw("startup trace initialized without console binding");
    initializeProcessDpiAwareness();
    startupTraceRaw("initializeProcessDpiAwareness finished");

    const std::vector<std::wstring> kStartupUnlockPathList = collectUnlockPathsFromCommandLine();
    // startupSettings must be read before the single-instance check: if the user disables 'prevent multiple instances', new launches must proceed to create an instance directly.
    ks::settings::AppearanceSettings startupSettings = ks::settings::loadAppearanceSettings();
    const bool kPrivilegeRestartLaunch = hasCommandLineArgument(kPrivilegeRestartArgument);
    const bool kSkipSingleInstanceLaunch = kCrashRestartWait;
    if (startupSettings.preventMultipleInstances && !kPrivilegeRestartLaunch && !kSkipSingleInstanceLaunch)
    {
        if (HWND existingWindowHandle = findExistingKswordMainWindow())
        {
            if (!kStartupUnlockPathList.empty())
            {
                startupTraceRaw("existing Ksword main window found, forwarding unlock request and exiting current instance");
                bool allUnlockRequestsForwarded = true;
                for (const std::wstring& unlockPath : kStartupUnlockPathList)
                {
                    if (!sendUnlockPathToExistingMainWindow(existingWindowHandle, unlockPath))
                    {
                        allUnlockRequestsForwarded = false;
                    }
                }

                if (!allUnlockRequestsForwarded && !isCurrentProcessElevated())
                {
                    // Fallback strategy:
                    // - The normal path should have ChangeWindowMessageFilterEx allow WM_COPYDATA via the existing main window.
                    // If the target instance is outdated, the window has not finished initializing, or system policy causes the send to fail, a non-elevated instance must not discard the path directly.
                    // - Attempt an elevated restart to ensure file unlock requests can enter a new instance with administrator privileges.
                    startupTraceRaw("unlock forwarding failed from non-elevated process, trying elevated relaunch fallback");
                    if (tryLaunchElevatedSelfBeforeSplash())
                    {
                        startupTraceRaw("unlock forwarding fallback elevated relaunch succeeded");
                        return 0;
                    }
                }
            }
            else
            {
                startupTraceRaw("existing Ksword main window found, activating it and exiting current instance");
            }
            activateExistingKswordMainWindow(existingWindowHandle);
            return 0;
        }
    }
    else if (kPrivilegeRestartLaunch)
    {
        startupTraceRaw("privilege restart marker found, skipping single-instance check");
    }
    else if (kSkipSingleInstanceLaunch)
    {
        startupTraceRaw("verified crash restart predecessor exited, skipping single-instance check");
    }
    else if (!startupSettings.preventMultipleInstances)
    {
        startupTraceRaw("prevent multiple instances disabled in settings, skipping single-instance check");
    }

    if (!kStartupUnlockPathList.empty() && !kPrivilegeRestartLaunch && !isCurrentProcessElevated())
    {
        // Shell file unlock entry must escalate privileges as early as possible:
        // - File lock scanning requires administrator privileges and SeDebugPrivilege; otherwise, system/high-privilege process handles may be missed;
        // - Located before splash/QApplication creation to avoid flickering caused by a normal-permission instance initializing the UI before restarting with elevation.
        // - Parameters are passed through verbatim from tryLaunchElevatedSelfBeforeSplash, with an internal restart flag appended to prevent loops.
        startupTraceRaw("unlock startup requested without elevation, launching elevated self before splash");
        KLogEvent unlockElevationEvent;
        info << unlockElevationEvent
            << "[main] 检测到文件解锁参数且当前不是管理员，准备立即提权重启。"
            << eol;
        const bool kElevatedLaunchStarted = tryLaunchElevatedSelfBeforeSplash();
        if (kElevatedLaunchStarted)
        {
            startupTraceRaw("unlock elevated relaunch succeeded, exiting current instance");
            warn << unlockElevationEvent
                << "[main] 文件解锁管理员实例已启动，当前普通权限实例退出。"
                << eol;
            return 0;
        }
        warn << unlockElevationEvent
            << "[main] 文件解锁管理员实例未能启动，将继续当前实例启动。"
            << eol;
    }

    {
        KLogEvent startupMainEvent;
        info << startupMainEvent
            << "[main] 进入主函数。 argc="
            << argc
            << eol;
    }

    // startupSettings: Caches the configuration snapshot required for the current startup.
    const std::wstring kExecutablePathForTrace = queryCurrentExecutablePath();
    const std::wstring kCurrentDirectoryForTrace = queryCurrentDirectoryPath();
    const QString kSettingsReadPath = ks::settings::resolveSettingsJsonPathForRead();
    const bool kSettingsFileExists = ks::settings::settingsJsonFileExistsForRead();
    startupTraceRaw(
        std::string("startup paths: cwd=")
        + QString::fromStdWString(kCurrentDirectoryForTrace).toUtf8().toStdString()
        + ", exe="
        + QString::fromStdWString(kExecutablePathForTrace).toUtf8().toStdString()
        + ", settings_path="
        + kSettingsReadPath.toUtf8().toStdString()
        + ", settings_exists="
        + (kSettingsFileExists ? "true" : "false"));

    QString preQtLanguageMessage;
    (void)ks::i18n::LanguageManager::instance().initialize(
        startupSettings.uiLanguage,
        &preQtLanguageMessage);
    startupTraceRaw(
        std::string("startup settings loaded: scale_factor=")
        + std::to_string(startupSettings.startupWindowScaleFactor)
        + ", startup_tab="
        + startupSettings.startupDefaultTabKey.toUtf8().toStdString()
        + ", startup_maximized="
        + (startupSettings.launchMaximizedOnStartup ? "true" : "false")
        + ", auto_admin="
        + (startupSettings.autoRequestAdminOnStartup ? "true" : "false")
        + ", auto_install_r0_driver="
        + (startupSettings.startupAutoInstallR0Driver ? "true" : "false")
        + ", prevent_multiple_instances="
        + (startupSettings.preventMultipleInstances ? "true" : "false"));
    {
        KLogEvent settingsEvent;
        info << settingsEvent
            << "[main] 启动配置已加载。 startup_tab="
            << startupSettings.startupDefaultTabKey
            << ", startup_maximized="
            << (startupSettings.launchMaximizedOnStartup ? "true" : "false")
            << ", auto_admin="
            << (startupSettings.autoRequestAdminOnStartup ? "true" : "false")
            << ", auto_install_r0_driver="
            << (startupSettings.startupAutoInstallR0Driver ? "true" : "false")
            << ", prevent_multiple_instances="
            << (startupSettings.preventMultipleInstances ? "true" : "false")
            << ", startup_scale_factor="
            << startupSettings.startupWindowScaleFactor
            << ", scale_prompt_disabled="
            << (startupSettings.startupScaleRecommendPromptDisabled ? "true" : "false")
            << eol;
    }

    startupTraceRaw("before maybeApplyStartupScaleRecommendation");
    if (maybeApplyStartupScaleRecommendation(&startupSettings))
    {
        startupTraceRaw("maybeApplyStartupScaleRecommendation returned true, exiting current instance");
        KLogEvent restartTakeoverEvent;
        warn << restartTakeoverEvent
            << "[main] maybeApplyStartupScaleRecommendation 返回 true，当前实例提前退出。"
            << eol;
        return 0;
    }

    if (startupSettings.autoRequestAdminOnStartup
        && !kPrivilegeRestartLaunch
        && !isCurrentProcessElevated())
    {
        startupTraceRaw("autoRequestAdminOnStartup enabled and process not elevated");
        KLogEvent adminRequestEvent;
        info << adminRequestEvent
            << "[main] 检测到启用自动管理员请求，准备在 splash 前尝试提权重启。"
            << eol;
        const bool kElevatedLaunchStarted = tryLaunchElevatedSelfBeforeSplash();
        if (kElevatedLaunchStarted)
        {
            startupTraceRaw("tryLaunchElevatedSelfBeforeSplash succeeded, exiting current instance");
            warn << adminRequestEvent
                << "[main] 管理员实例已启动，当前普通权限实例退出。"
                << eol;
            return 0;
        }
        warn << adminRequestEvent
            << "[main] 自动管理员请求未拉起新实例，将继续当前实例启动。"
            << eol;
    }

    // Administrator instances must enable common process token privileges as early as possible before the main window is created:
    // - When started with admin/--ksword-privilege-restart parameters, the button click flow is skipped;
    // - Therefore, request privileges in batches before creating the QApplication (lines 30-52) to prevent degradation of process/handle/R0/backup-restore features.
    startupTraceRaw("before startup process privilege request");
    (void)tryEnableStartupProcessPrivileges();
    startupTraceRaw("after startup process privilege request");

    startupTraceRaw("before applyQtScaleFactorEnvironment");
    applyQtScaleFactorEnvironment(startupSettings.startupWindowScaleFactor);
    startupTraceRaw("after applyQtScaleFactorEnvironment");

    const bool kSplashReady = kSplash.show(
        localizedStartupText(
            QStringLiteral("main.startup.progress.starting"),
            QStringLiteral("正在启动..."))
            .toUtf8()
            .toStdString());
    startupTraceRaw(std::string("kSplash.show finished, result=") + (kSplashReady ? "true" : "false"));
    {
        KLogEvent splashEvent;
        info << splashEvent
            << "[main] 启动画面 show 结果="
            << (kSplashReady ? "true" : "false")
            << eol;
    }
    if (kSplashReady)
    {
        updateStartupSplash(
            kSplashReady,
            6,
            QStringLiteral("main.startup.progress.qt_runtime"),
            QStringLiteral("正在准备运行环境..."));
    }

    startupTraceRaw("before QApplication construction");
    QApplication app(argc, argv);
    startupTraceRaw("QApplication constructed");
    disableQtPopupScrollEffects();

    // Organization name and application name must be set before any QSettings is constructed: the default-constructed QSettings uses these values to locate
    // HKCU\Software\<Organization>\<Application>. If the organization name is empty, Qt's Windows registry backend immediately sets AccessError, causing
    // reads to always return default values and writes to be silently dropped. This was the exact state of this program previously, resulting in the 'Do not
    // show this confirmation again' checkbox having no effect, and plugin auto-update switches and plugin license acceptance records failing to persist.
    // With this addition, the above three links become truly usable; key names retain the existing group prefixes from each call site without migration.
    QCoreApplication::setOrganizationName(QStringLiteral("Ksword"));
    QCoreApplication::setApplicationName(QStringLiteral("Ksword5.1"));

    // startupSystemFont:
    // - Save the complete Qt/system-provided font baseline before reading and applying any persistent font family.
    // - Subsequent restoration of 'System Default' must use this value; it cannot be inferred from QApplication::font() which may be polluted by configuration.
    const QFont kStartupSystemFont = app.font();
    // startupApplicationFont:
    // - Restore saved fonts before creating mainWindow and any Dock/tables.
    // - Avoid the table binding to the system default font first, then only updating some controls when changing the QApplication font.
    QFont startupApplicationFont = kStartupSystemFont;
    const QString kStartupFontFamily = startupSettings.fontFamily.trimmed();
    if (!kStartupFontFamily.isEmpty())
    {
        startupApplicationFont.setFamily(kStartupFontFamily);
    }
    startupApplicationFont.setStyleStrategy(
        startupSettings.textAntialiasingEnabled
        ? QFont::PreferAntialias
        : QFont::NoAntialias);
    QApplication::setFont(startupApplicationFont);

    QString languageLoadMessage;
    const bool kLanguagePackLoaded = ks::i18n::LanguageManager::instance().initialize(
        startupSettings.uiLanguage,
        &languageLoadMessage);
    {
        KLogEvent languageEvent;
        info << languageEvent
            << "[main] Language system initialized. requested="
            << startupSettings.uiLanguage
            << ", active="
            << ks::i18n::LanguageManager::instance().currentLanguageId()
            << ", loaded="
            << (kLanguagePackLoaded ? "true" : "false")
            << ", detail="
            << languageLoadMessage
            << eol;
    }
    const std::wstring kCrashTitle = localizedStartupText(
        QStringLiteral("main.crash.title"),
        QStringLiteral("KswordARK 崩溃")).toStdWString();
    const std::wstring kCrashInstruction = localizedStartupText(
        QStringLiteral("main.crash.instruction"),
        QStringLiteral("KswordARK 因未处理的异常停止运行。")).toStdWString();
    const std::wstring kCrashExceptionCode = localizedStartupText(
        QStringLiteral("main.crash.exception_code"),
        QStringLiteral("异常")).toStdWString();
    const std::wstring kCrashExceptionAddress = localizedStartupText(
        QStringLiteral("main.crash.exception_address"),
        QStringLiteral("地址")).toStdWString();
    const std::wstring kCrashDumpPath = localizedStartupText(
        QStringLiteral("main.crash.dump_path"),
        QStringLiteral("转储文件")).toStdWString();
    const std::wstring kCrashDumpUnavailable = localizedStartupText(
        QStringLiteral("main.crash.dump_unavailable"),
        QStringLiteral("转储文件未能写入。")).toStdWString();
    const std::wstring kCrashRestartQuestion = localizedStartupText(
        QStringLiteral("main.crash.restart_question"),
        QStringLiteral("选择“是”重新启动 KswordARK，选择“否”退出。")).toStdWString();
    const std::wstring kCrashRepeated = localizedStartupText(
        QStringLiteral("main.crash.repeated"),
        QStringLiteral("程序刚刚重启后再次崩溃，建议先退出并检查转储文件。")).toStdWString();
    const std::wstring kCrashRestartFailed = localizedStartupText(
        QStringLiteral("main.crash.restart_failed"),
        QStringLiteral("重新启动 KswordARK 失败，程序即将退出。")).toStdWString();
    ks::crash::DialogText crashDialogText;
    crashDialogText.title = kCrashTitle.c_str();
    crashDialogText.instruction = kCrashInstruction.c_str();
    crashDialogText.exceptionCodeLabel = kCrashExceptionCode.c_str();
    crashDialogText.exceptionAddressLabel = kCrashExceptionAddress.c_str();
    crashDialogText.dumpPathLabel = kCrashDumpPath.c_str();
    crashDialogText.dumpUnavailableText = kCrashDumpUnavailable.c_str();
    crashDialogText.restartQuestion = kCrashRestartQuestion.c_str();
    crashDialogText.repeatedCrashText = kCrashRepeated.c_str();
    crashDialogText.restartFailedText = kCrashRestartFailed.c_str();
    ks::crash::updateCrashDialogText(crashDialogText);
    ks::ui::installGlobalMessageBoxTheme(&app);
    startupTraceRaw("InstallGlobalMessageBoxTheme finished");
    ks::ui::installGlobalDialogTheme(&app);
    startupTraceRaw("InstallGlobalDialogTheme finished");
    ks::ui::installWindowChrome(&app);
    startupTraceRaw("InstallWindowChrome finished");
    ks::ui::installGlobalRefreshShortcut(&app);
    startupTraceRaw("InstallGlobalRefreshShortcut finished");
    ks::ui::installGlobalTableColumnAutoFit(&app);
    startupTraceRaw("InstallGlobalTableColumnAutoFit finished");
    ks::ui::installGlobalTableInteractionSupport(&app);
    ks::ui::installGlobalSmoothScrollSupport(&app);
    // Unified Ctrl+F search / Ctrl+H replace (with regex toggle) support for all multi-line text boxes in the application.
    ks::ui::installGlobalTextSearchReplaceSupport(&app);
    const QStringList kArgumentList = QCoreApplication::arguments();
    startupTraceRaw(
        std::string("QCoreApplication::arguments fetched, count=")
        + std::to_string(kArgumentList.size()));
    {
        KLogEvent argumentEvent;
        info << argumentEvent
            << "[main] QApplication 已创建。 argument_count="
            << kArgumentList.size()
            << eol;
    }

    const bool kShouldRegisterUnlockerMenu = kArgumentList.contains(QStringLiteral("--register-unlocker-context-menu"));
    const bool kShouldUnregisterUnlockerMenu = kArgumentList.contains(QStringLiteral("--unregister-unlocker-context-menu"));
    if (kShouldRegisterUnlockerMenu || kShouldUnregisterUnlockerMenu)
    {
        if (kShouldUnregisterUnlockerMenu)
        {
            unregisterUnlockerContextMenu();
            startupSettings.unlockerShellContextMenuEnabled = false;
            QString saveErrorText;
            ks::settings::saveAppearanceSettings(startupSettings, &saveErrorText);
            QMessageBox::information(
                nullptr,
                localizedStartupText(
                    QStringLiteral("main.unlocker.dialog.title"),
                    QStringLiteral("Ksword 文件解锁器")),
                localizedStartupText(
                    QStringLiteral("main.unlocker.dialog.removed"),
                    QStringLiteral("已移除系统右键菜单中的“Ksword 文件解锁器(R3/R0)”项。")));
            return 0;
        }

        const std::wstring kExecutablePath = queryCurrentExecutablePath();
        if (kExecutablePath.empty())
        {
            QMessageBox::warning(
                nullptr,
                localizedStartupText(
                    QStringLiteral("main.unlocker.dialog.title"),
                    QStringLiteral("Ksword 文件解锁器")),
                localizedStartupText(
                    QStringLiteral("main.unlocker.dialog.path_failed"),
                    QStringLiteral("读取程序路径失败，无法注册系统右键菜单。")));
            return 1;
        }

        const bool kRegisterOk = registerUnlockerContextMenu(kExecutablePath);
        if (kRegisterOk)
        {
            startupSettings.unlockerShellContextMenuEnabled = true;
            QString saveErrorText;
            ks::settings::saveAppearanceSettings(startupSettings, &saveErrorText);
            QMessageBox::information(
                nullptr,
                localizedStartupText(
                    QStringLiteral("main.unlocker.dialog.title"),
                    QStringLiteral("Ksword 文件解锁器")),
                localizedStartupText(
                    QStringLiteral("main.unlocker.dialog.registered"),
                    QStringLiteral("已注册系统右键菜单，可在文件/目录/磁盘和目录空白处右键触发。")));
            return 0;
        }

        QMessageBox::warning(
            nullptr,
            localizedStartupText(
                QStringLiteral("main.unlocker.dialog.title"),
                QStringLiteral("Ksword 文件解锁器")),
            localizedStartupText(
                QStringLiteral("main.unlocker.dialog.register_failed"),
                QStringLiteral("注册系统右键菜单失败，请确认当前账户对 HKCU\\Software\\Classes 具备写入权限。")));
        return 1;
    }

    // On normal startup: synchronize the system context menu 'File Unlocker' based on the settings page toggle.
    {
        const std::wstring kExecutablePath = queryCurrentExecutablePath();
        if (!kExecutablePath.empty())
        {
            if (startupSettings.unlockerShellContextMenuEnabled)
            {
                registerUnlockerContextMenu(kExecutablePath);
            }
            else
            {
                unregisterUnlockerContextMenu();
            }
        }
    }

    QStringList unlockPathList;
    for (const std::wstring& unlockPath : kStartupUnlockPathList)
    {
        unlockPathList.push_back(QString::fromStdWString(unlockPath));
    }

    // startupProgressCallback:
    // - Receive callbacks during mainWindow construction.
    // - Continuously update the startup page text and progress percentage.
    const MainWindow::StartupProgressCallback kStartupProgressCallback =
        [kSplashReady](const int progressPercent, const QString& statusText)
        {
            // Write the progress point to the startup trace file simultaneously:
            // - Trace lines include millisecond timestamps so that the segmented time consumption during main window construction can be observed.
            // - Unaffected by splashReady; leaves a timeline even when no splash screen is present.
            startupTraceRaw(
                "startup_progress " + std::to_string(progressPercent) + "%: "
                + statusText.toUtf8().toStdString());
            if (!kSplashReady)
            {
                return;
            }
            kSplash.progress(statusText.toUtf8().toStdString(), progressPercent);
            KLogEvent splashProgressEvent;
            info << splashProgressEvent
                << "[main] StartupProgressCallback progress="
                << progressPercent
                << ", status="
                << statusText
                << eol;
        };

    if (kSplashReady)
    {
        updateStartupSplash(
            kSplashReady,
            18,
            QStringLiteral("main.startup.progress.prepare_environment"),
            QStringLiteral("正在准备运行环境..."));
        updateStartupSplash(
            kSplashReady,
            28,
            QStringLiteral("main.startup.progress.create_main_window"),
            QStringLiteral("正在准备主界面..."));
    }

    MainWindow window(nullptr, kStartupProgressCallback, kStartupSystemFont);
    startupTraceRaw("MainWindow constructed");
    {
        KLogEvent windowConstructEvent;
        info << windowConstructEvent
            << "[main] MainWindow 构造已完成。 visible="
            << (window.isVisible() ? "true" : "false")
            << ", geometry="
            << window.geometry().x()
            << ","
            << window.geometry().y()
            << " "
            << window.geometry().width()
            << "x"
            << window.geometry().height()
            << eol;
    }
    FirstFrameSplashHider firstFrameHider(&window, &kSplash);
    window.installEventFilter(&firstFrameHider);
    if (window.centralWidget() != nullptr)
    {
        window.centralWidget()->installEventFilter(&firstFrameHider);
    }

    if (kSplashReady)
    {
        updateStartupSplash(
            kSplashReady,
            95,
            QStringLiteral("main.startup.progress.show_main_window"),
            QStringLiteral("即将完成..."));
    }

    if (startupSettings.launchMaximizedOnStartup)
    {
        window.showMaximized();
    }
    else
    {
        window.show();
    }

    // Preconditions for starting the main window:
    // - Execute only once after the main window's first show/showMaximized completes.
    // - Ensure consistent foreground activation behavior for both normal startup and --unlock startup.
    window.raise();
    window.activateWindow();

    startupTraceRaw("window.show invoked");
    {
        KLogEvent showEvent;
        const QRect kVisibleGeometry = window.frameGeometry();
        info << showEvent
            << "[main] 已调用 window.show()。 isVisible="
            << (window.isVisible() ? "true" : "false")
            << ", isMinimized="
            << (window.isMinimized() ? "true" : "false")
            << ", frame="
            << kVisibleGeometry.x()
            << ","
            << kVisibleGeometry.y()
            << " "
            << kVisibleGeometry.width()
            << "x"
            << kVisibleGeometry.height()
            << eol;
    }
    applyNativeAppIconToWidget(&window);

    if (isCurrentProcessElevated())
    {
        QTimer::singleShot(0, &window, []()
            {
                (void)tryLaunchUacDeskCompanion();
            });
    }

    if (!unlockPathList.isEmpty())
    {
        const QStringList kPendingUnlockPathList = unlockPathList;
        QTimer::singleShot(1600, &window, [&window, kPendingUnlockPathList]()
            {
                kSplash.hide();
                for (const QString& targetPath : kPendingUnlockPathList)
                {
                    QTimer::singleShot(0, &window, [&window, targetPath]()
                        {
                            window.openFileUnlockerDockByPath(targetPath);
                        });
                }
            });
    }

    if (kSplashReady)
    {
        updateStartupSplash(
            kSplashReady,
            98,
            QStringLiteral("main.startup.progress.wait_first_frame"),
            QStringLiteral("即将完成..."));

        // Fallback strategy:
        // - If the first frame event fails to trigger;
        // - Silently force-hide the splash screen after 4 seconds to avoid triggering user-facing warning notifications as a fallback action.
        QTimer::singleShot(4000, &window, []()
            {
                kSplash.hide();
            });
    }

    QTimer::singleShot(200, &window, [&window]()
        {
            KLogEvent firstSnapshotEvent;
            const QRect kSnapshotFrame = window.frameGeometry();
            info << firstSnapshotEvent
                << "[main] 启动后 200ms 窗口快照。 visible="
                << (window.isVisible() ? "true" : "false")
                << ", minimized="
                << (window.isMinimized() ? "true" : "false")
                << ", active="
                << (window.isActiveWindow() ? "true" : "false")
                << ", frame="
                << kSnapshotFrame.x()
                << ","
                << kSnapshotFrame.y()
                << " "
                << kSnapshotFrame.width()
                << "x"
                << kSnapshotFrame.height()
                << eol;
        });

    QTimer::singleShot(1200, &window, [&window]()
        {
            KLogEvent secondSnapshotEvent;
            const QRect kSnapshotFrame = window.frameGeometry();
            info << secondSnapshotEvent
                << "[main] 启动后 1200ms 窗口快照。 visible="
                << (window.isVisible() ? "true" : "false")
                << ", minimized="
                << (window.isMinimized() ? "true" : "false")
                << ", active="
                << (window.isActiveWindow() ? "true" : "false")
                << ", frame="
                << kSnapshotFrame.x()
                << ","
                << kSnapshotFrame.y()
                << " "
                << kSnapshotFrame.width()
                << "x"
                << kSnapshotFrame.height()
                << eol;
        });

    const int kExitCode = app.exec();
    startupTraceRaw(std::string("QApplication::exec returned, exitCode=") + std::to_string(kExitCode));
    {
        KLogEvent exitLoopEvent;
        info << exitLoopEvent
            << "[main] QApplication::exec() 已返回。 exitCode="
            << kExitCode
            << eol;
    }
    kSplash.hide();
    return kExitCode;
}

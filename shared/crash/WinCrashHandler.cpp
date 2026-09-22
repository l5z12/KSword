#include "WinCrashHandler.h"

#include <DbgHelp.h>
#include <Shellapi.h>
#include <TlHelp32.h>
#include <strsafe.h>

#include <cstddef>
#include <cwchar>

#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "User32.lib")

namespace ks
{
    namespace crash
    {
        const wchar_t kCrashRestartWaitPidArgument[] = L"--ksword-crash-restart-wait-pid";
        const wchar_t kCrashRestartedArgument[] = L"--ksword-crash-restarted";

        namespace
        {
            using MiniDumpWriteDumpFunction = BOOL(WINAPI*)(
                HANDLE,
                DWORD,
                HANDLE,
                MINIDUMP_TYPE,
                PMINIDUMP_EXCEPTION_INFORMATION,
                PMINIDUMP_USER_STREAM_INFORMATION,
                PMINIDUMP_CALLBACK_INFORMATION);

            struct CrashState
            {
                volatile LONG handling = 0;
                bool installed = false;
                bool chinese = false;
                bool preferLauncherReporter = false;
                bool restartAlreadyAttempted = false;
                HMODULE dbgHelpModule = nullptr;
                MiniDumpWriteDumpFunction miniDumpWriteDump = nullptr;

                wchar_t productName[128] = {};
                wchar_t dumpFilePrefix[128] = {};
                wchar_t executablePath[32768] = {};
                wchar_t executableDirectory[32768] = {};
                wchar_t launcherPath[32768] = {};
                wchar_t dumpDirectory[32768] = {};

                wchar_t title[256] = {};
                wchar_t instruction[512] = {};
                wchar_t exceptionCodeLabel[128] = {};
                wchar_t exceptionAddressLabel[128] = {};
                wchar_t dumpPathLabel[128] = {};
                wchar_t dumpUnavailableText[256] = {};
                wchar_t restartQuestion[256] = {};
                wchar_t repeatedCrashText[256] = {};
                wchar_t restartFailedText[256] = {};
            };

            CrashState gState;

            void copyText(wchar_t* destination, const std::size_t destinationCount, const wchar_t* source)
            {
                if (destination == nullptr || destinationCount == 0 || source == nullptr)
                {
                    return;
                }
                (void)::StringCchCopyW(destination, destinationCount, source);
            }

            bool isChineseSystemUi()
            {
                return PRIMARYLANGID(::GetUserDefaultUILanguage()) == LANG_CHINESE;
            }

            void initializeDefaultDialogText()
            {
                if (gState.chinese)
                {
                    copyText(gState.title, ARRAYSIZE(gState.title), L"KswordARK 崩溃");
                    copyText(gState.instruction, ARRAYSIZE(gState.instruction), L"KswordARK 因未处理的异常停止运行。");
                    copyText(gState.exceptionCodeLabel, ARRAYSIZE(gState.exceptionCodeLabel), L"异常");
                    copyText(gState.exceptionAddressLabel, ARRAYSIZE(gState.exceptionAddressLabel), L"地址");
                    copyText(gState.dumpPathLabel, ARRAYSIZE(gState.dumpPathLabel), L"转储文件");
                    copyText(gState.dumpUnavailableText, ARRAYSIZE(gState.dumpUnavailableText), L"转储文件未能写入。");
                    copyText(gState.restartQuestion, ARRAYSIZE(gState.restartQuestion), L"选择“是”重新启动 KswordARK，选择“否”退出。");
                    copyText(gState.repeatedCrashText, ARRAYSIZE(gState.repeatedCrashText), L"程序刚刚重启后再次崩溃，建议先退出并检查转储文件。");
                    copyText(gState.restartFailedText, ARRAYSIZE(gState.restartFailedText), L"重新启动 KswordARK 失败，程序即将退出。");
                }
                else
                {
                    copyText(gState.title, ARRAYSIZE(gState.title), L"KswordARK crashed");
                    copyText(gState.instruction, ARRAYSIZE(gState.instruction), L"KswordARK stopped because of an unhandled exception.");
                    copyText(gState.exceptionCodeLabel, ARRAYSIZE(gState.exceptionCodeLabel), L"Exception");
                    copyText(gState.exceptionAddressLabel, ARRAYSIZE(gState.exceptionAddressLabel), L"Address");
                    copyText(gState.dumpPathLabel, ARRAYSIZE(gState.dumpPathLabel), L"Dump file");
                    copyText(gState.dumpUnavailableText, ARRAYSIZE(gState.dumpUnavailableText), L"The dump file could not be written.");
                    copyText(gState.restartQuestion, ARRAYSIZE(gState.restartQuestion), L"Choose Yes to restart KswordARK, or No to exit.");
                    copyText(gState.repeatedCrashText, ARRAYSIZE(gState.repeatedCrashText), L"The program crashed again immediately after a restart. Exit and inspect the dump file.");
                    copyText(gState.restartFailedText, ARRAYSIZE(gState.restartFailedText), L"KswordARK could not be restarted and will now exit.");
                }
            }

            void resolveExecutablePaths()
            {
                gState.executablePath[0] = L'\0';
                (void)::GetModuleFileNameW(
                    nullptr,
                    gState.executablePath,
                    static_cast<DWORD>(ARRAYSIZE(gState.executablePath)));

                copyText(
                    gState.executableDirectory,
                    ARRAYSIZE(gState.executableDirectory),
                    gState.executablePath);
                wchar_t* const kSeparator = wcsrchr(gState.executableDirectory, L'\\');
                wchar_t* const kAlternateSeparator = wcsrchr(gState.executableDirectory, L'/');
                wchar_t* finalSeparator = kSeparator;
                if (finalSeparator == nullptr
                    || (kAlternateSeparator != nullptr && kAlternateSeparator > finalSeparator))
                {
                    finalSeparator = kAlternateSeparator;
                }
                if (finalSeparator != nullptr)
                {
                    *finalSeparator = L'\0';
                }
                else
                {
                    copyText(gState.executableDirectory, ARRAYSIZE(gState.executableDirectory), L".");
                }

                (void)::StringCchPrintfW(
                    gState.launcherPath,
                    ARRAYSIZE(gState.launcherPath),
                    L"%s\\Launcher.exe",
                    gState.executableDirectory);
            }

            bool ensureCrashDirectory()
            {
                wchar_t baseDirectory[32768] = {};
                DWORD copied = ::GetEnvironmentVariableW(
                    L"LOCALAPPDATA",
                    baseDirectory,
                    static_cast<DWORD>(ARRAYSIZE(baseDirectory)));
                if (copied == 0 || copied >= ARRAYSIZE(baseDirectory))
                {
                    copied = ::GetTempPathW(
                        static_cast<DWORD>(ARRAYSIZE(baseDirectory)),
                        baseDirectory);
                    if (copied == 0 || copied >= ARRAYSIZE(baseDirectory))
                    {
                        return false;
                    }
                }

                wchar_t productDirectory[32768] = {};
                if (FAILED(::StringCchPrintfW(
                    productDirectory,
                    ARRAYSIZE(productDirectory),
                    L"%s\\KswordARK",
                    baseDirectory)))
                {
                    return false;
                }
                (void)::CreateDirectoryW(productDirectory, nullptr);

                if (FAILED(::StringCchPrintfW(
                    gState.dumpDirectory,
                    ARRAYSIZE(gState.dumpDirectory),
                    L"%s\\CrashDumps",
                    productDirectory)))
                {
                    return false;
                }
                if (::CreateDirectoryW(gState.dumpDirectory, nullptr) != FALSE
                    || ::GetLastError() == ERROR_ALREADY_EXISTS)
                {
                    return true;
                }

                wchar_t temporaryDirectory[32768] = {};
                copied = ::GetTempPathW(
                    static_cast<DWORD>(ARRAYSIZE(temporaryDirectory)),
                    temporaryDirectory);
                if (copied == 0 || copied >= ARRAYSIZE(temporaryDirectory))
                {
                    return false;
                }
                if (FAILED(::StringCchPrintfW(
                    gState.dumpDirectory,
                    ARRAYSIZE(gState.dumpDirectory),
                    L"%sKswordARK-CrashDumps",
                    temporaryDirectory)))
                {
                    return false;
                }
                return ::CreateDirectoryW(gState.dumpDirectory, nullptr) != FALSE
                    || ::GetLastError() == ERROR_ALREADY_EXISTS;
            }

            const wchar_t* exceptionDescription(const DWORD exceptionCode)
            {
                if (gState.chinese)
                {
                    switch (exceptionCode)
                    {
                    case EXCEPTION_ACCESS_VIOLATION: return L"访问冲突";
                    case EXCEPTION_ILLEGAL_INSTRUCTION: return L"非法指令";
                    case EXCEPTION_INT_DIVIDE_BY_ZERO: return L"整数除零";
                    case EXCEPTION_STACK_OVERFLOW: return L"栈溢出";
                    case STATUS_HEAP_CORRUPTION: return L"堆损坏";
                    case 0xE06D7363u: return L"未处理的 C++ 异常";
                    default: return L"未处理异常";
                    }
                }

                switch (exceptionCode)
                {
                case EXCEPTION_ACCESS_VIOLATION: return L"Access violation";
                case EXCEPTION_ILLEGAL_INSTRUCTION: return L"Illegal instruction";
                case EXCEPTION_INT_DIVIDE_BY_ZERO: return L"Integer divide by zero";
                case EXCEPTION_STACK_OVERFLOW: return L"Stack overflow";
                case STATUS_HEAP_CORRUPTION: return L"Heap corruption";
                case 0xE06D7363u: return L"Unhandled C++ exception";
                default: return L"Unhandled exception";
                }
            }

            bool writeMinidump(
                PEXCEPTION_POINTERS exceptionPointers,
                wchar_t* dumpPath,
                const std::size_t dumpPathCount)
            {
                if (dumpPath == nullptr || dumpPathCount == 0 || gState.miniDumpWriteDump == nullptr)
                {
                    return false;
                }

                SYSTEMTIME localTime = {};
                ::GetLocalTime(&localTime);
                if (FAILED(::StringCchPrintfW(
                    dumpPath,
                    dumpPathCount,
                    L"%s\\%s-%04u%02u%02u-%02u%02u%02u-%lu.dmp",
                    gState.dumpDirectory,
                    gState.dumpFilePrefix,
                    static_cast<unsigned int>(localTime.wYear),
                    static_cast<unsigned int>(localTime.wMonth),
                    static_cast<unsigned int>(localTime.wDay),
                    static_cast<unsigned int>(localTime.wHour),
                    static_cast<unsigned int>(localTime.wMinute),
                    static_cast<unsigned int>(localTime.wSecond),
                    static_cast<unsigned long>(::GetCurrentProcessId()))))
                {
                    dumpPath[0] = L'\0';
                    return false;
                }

                HANDLE dumpFile = ::CreateFileW(
                    dumpPath,
                    GENERIC_WRITE,
                    FILE_SHARE_READ,
                    nullptr,
                    CREATE_NEW,
                    FILE_ATTRIBUTE_NORMAL,
                    nullptr);
                if (dumpFile == INVALID_HANDLE_VALUE)
                {
                    return false;
                }

                MINIDUMP_EXCEPTION_INFORMATION exceptionInformation = {};
                exceptionInformation.ThreadId = ::GetCurrentThreadId();
                exceptionInformation.ExceptionPointers = exceptionPointers;
                exceptionInformation.ClientPointers = FALSE;
                const MINIDUMP_TYPE kDumpType = static_cast<MINIDUMP_TYPE>(
                    MiniDumpNormal
                    | MiniDumpWithThreadInfo
                    | MiniDumpWithUnloadedModules
                    | MiniDumpWithIndirectlyReferencedMemory);
                const BOOL kWriteOk = gState.miniDumpWriteDump(
                    ::GetCurrentProcess(),
                    ::GetCurrentProcessId(),
                    dumpFile,
                    kDumpType,
                    exceptionPointers != nullptr ? &exceptionInformation : nullptr,
                    nullptr,
                    nullptr);
                ::CloseHandle(dumpFile);
                return kWriteOk != FALSE;
            }

            bool launchSelfForRestart()
            {
                wchar_t commandLine[32768] = {};
                if (FAILED(::StringCchPrintfW(
                    commandLine,
                    ARRAYSIZE(commandLine),
                    L"\"%s\" %s %lu %s",
                    gState.executablePath,
                    kCrashRestartWaitPidArgument,
                    static_cast<unsigned long>(::GetCurrentProcessId()),
                    kCrashRestartedArgument)))
                {
                    return false;
                }

                STARTUPINFOW startupInfo = {};
                startupInfo.cb = sizeof(startupInfo);
                startupInfo.dwFlags = STARTF_USESHOWWINDOW;
                startupInfo.wShowWindow = SW_SHOWNORMAL;
                PROCESS_INFORMATION processInformation = {};
                const BOOL kCreateOk = ::CreateProcessW(
                    gState.executablePath,
                    commandLine,
                    nullptr,
                    nullptr,
                    FALSE,
                    0,
                    nullptr,
                    gState.executableDirectory,
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

            bool launchExternalReporter(
                const DWORD exceptionCode,
                const ULONG_PTR exceptionAddress,
                const wchar_t* dumpPath,
                const bool dumpWritten)
            {
                if (!gState.preferLauncherReporter
                    || gState.launcherPath[0] == L'\0'
                    || ::GetFileAttributesW(gState.launcherPath) == INVALID_FILE_ATTRIBUTES)
                {
                    return false;
                }

                wchar_t eventName[128] = {};
                if (FAILED(::StringCchPrintfW(
                    eventName,
                    ARRAYSIZE(eventName),
                    L"Local\\KswordARKCrashReady_%lu_%lu",
                    static_cast<unsigned long>(::GetCurrentProcessId()),
                    static_cast<unsigned long>(::GetCurrentThreadId()))))
                {
                    return false;
                }
                HANDLE readyEvent = ::CreateEventW(nullptr, TRUE, FALSE, eventName);
                if (readyEvent == nullptr)
                {
                    return false;
                }

                wchar_t commandLine[32768] = {};
                const HRESULT kFormatResult = ::StringCchPrintfW(
                    commandLine,
                    ARRAYSIZE(commandLine),
                    L"\"%s\" --launcher-crash-report --launcher-crash-pid %lu "
                    L"--launcher-crash-code 0x%08lX --launcher-crash-address 0x%llX "
                    L"--launcher-crash-dump \"%s\" --launcher-crash-dump-written %u "
                    L"--launcher-crash-ready-event \"%s\"%s",
                    gState.launcherPath,
                    static_cast<unsigned long>(::GetCurrentProcessId()),
                    static_cast<unsigned long>(exceptionCode),
                    static_cast<unsigned long long>(exceptionAddress),
                    dumpPath == nullptr ? L"" : dumpPath,
                    dumpWritten ? 1u : 0u,
                    eventName,
                    gState.restartAlreadyAttempted ? L" --launcher-crash-repeat" : L"");
                if (FAILED(kFormatResult))
                {
                    ::CloseHandle(readyEvent);
                    return false;
                }

                STARTUPINFOW startupInfo = {};
                startupInfo.cb = sizeof(startupInfo);
                startupInfo.dwFlags = STARTF_USESHOWWINDOW;
                startupInfo.wShowWindow = SW_SHOWNORMAL;
                PROCESS_INFORMATION processInformation = {};
                const BOOL kCreateOk = ::CreateProcessW(
                    gState.launcherPath,
                    commandLine,
                    nullptr,
                    nullptr,
                    FALSE,
                    0,
                    nullptr,
                    gState.executableDirectory,
                    &startupInfo,
                    &processInformation);
                if (kCreateOk == FALSE)
                {
                    ::CloseHandle(readyEvent);
                    return false;
                }

                const DWORD kWaitResult = ::WaitForSingleObject(readyEvent, 5000);
                ::CloseHandle(processInformation.hThread);
                ::CloseHandle(processInformation.hProcess);
                ::CloseHandle(readyEvent);
                return kWaitResult == WAIT_OBJECT_0;
            }

            int showLocalCrashDialog(
                const DWORD exceptionCode,
                const ULONG_PTR exceptionAddress,
                const wchar_t* dumpPath,
                const bool dumpWritten)
            {
                wchar_t message[8192] = {};
                const wchar_t* const kDescription = exceptionDescription(exceptionCode);
                const wchar_t* const kPathText = dumpWritten && dumpPath != nullptr && dumpPath[0] != L'\0'
                    ? dumpPath
                    : gState.dumpUnavailableText;
                const HRESULT kFormatResult = ::StringCchPrintfW(
                    message,
                    ARRAYSIZE(message),
                    L"%s\r\n\r\n%s: %s (0x%08lX)\r\n%s: 0x%llX\r\n%s: %s\r\n\r\n%s%s",
                    gState.instruction,
                    gState.exceptionCodeLabel,
                    kDescription,
                    static_cast<unsigned long>(exceptionCode),
                    gState.exceptionAddressLabel,
                    static_cast<unsigned long long>(exceptionAddress),
                    gState.dumpPathLabel,
                    kPathText,
                    gState.restartAlreadyAttempted ? gState.repeatedCrashText : L"",
                    gState.restartAlreadyAttempted ? L"\r\n\r\n" : gState.restartQuestion);
                if (FAILED(kFormatResult))
                {
                    return IDNO;
                }

                const UINT kFlags = (gState.restartAlreadyAttempted ? MB_OK : MB_YESNO)
                    | MB_ICONERROR
                    | MB_DEFBUTTON2
                    | MB_SETFOREGROUND
                    | MB_TOPMOST;
                return static_cast<int>(::MessageBoxW(nullptr, message, gState.title, kFlags));
            }

            LONG WINAPI topLevelExceptionFilter(PEXCEPTION_POINTERS exceptionPointers)
            {
                if (::InterlockedCompareExchange(&gState.handling, 1, 0) != 0)
                {
                    return EXCEPTION_EXECUTE_HANDLER;
                }

                const DWORD kExceptionCode = exceptionPointers != nullptr
                    && exceptionPointers->ExceptionRecord != nullptr
                    ? exceptionPointers->ExceptionRecord->ExceptionCode
                    : ERROR_UNHANDLED_EXCEPTION;
                const ULONG_PTR kExceptionAddress = exceptionPointers != nullptr
                    && exceptionPointers->ExceptionRecord != nullptr
                    ? reinterpret_cast<ULONG_PTR>(exceptionPointers->ExceptionRecord->ExceptionAddress)
                    : 0;
                wchar_t dumpPath[32768] = {};
                const bool kDumpWritten = writeMinidump(exceptionPointers, dumpPath, ARRAYSIZE(dumpPath));

                if (launchExternalReporter(kExceptionCode, kExceptionAddress, dumpPath, kDumpWritten))
                {
                    return EXCEPTION_EXECUTE_HANDLER;
                }

                const int kDialogResult = showLocalCrashDialog(
                    kExceptionCode,
                    kExceptionAddress,
                    dumpPath,
                    kDumpWritten);
                if (kDialogResult == IDYES && !gState.restartAlreadyAttempted)
                {
                    if (!launchSelfForRestart())
                    {
                        (void)::MessageBoxW(
                            nullptr,
                            gState.restartFailedText,
                            gState.title,
                            MB_OK | MB_ICONERROR | MB_SETFOREGROUND | MB_TOPMOST);
                    }
                }
                return EXCEPTION_EXECUTE_HANDLER;
            }

            bool tryReadArgumentValue(const wchar_t* argumentName, unsigned long long* value)
            {
                if (argumentName == nullptr || value == nullptr)
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
                for (int index = 1; index + 1 < argumentCount; ++index)
                {
                    if (_wcsicmp(argumentVector[index], argumentName) == 0)
                    {
                        wchar_t* end = nullptr;
                        const unsigned long long kParsed = _wcstoui64(argumentVector[index + 1], &end, 0);
                        if (end != argumentVector[index + 1] && *end == L'\0')
                        {
                            *value = kParsed;
                            found = true;
                        }
                        break;
                    }
                }
                ::LocalFree(argumentVector);
                return found;
            }

            bool isCurrentProcessDirectChildOf(const DWORD expectedParentProcessId)
            {
                HANDLE snapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
                if (snapshot == INVALID_HANDLE_VALUE)
                {
                    return false;
                }

                PROCESSENTRY32W entry = {};
                entry.dwSize = sizeof(entry);
                bool matches = false;
                if (::Process32FirstW(snapshot, &entry) != FALSE)
                {
                    do
                    {
                        if (entry.th32ProcessID == ::GetCurrentProcessId())
                        {
                            matches = entry.th32ParentProcessID == expectedParentProcessId;
                            break;
                        }
                    } while (::Process32NextW(snapshot, &entry) != FALSE);
                }
                ::CloseHandle(snapshot);
                return matches;
            }

            bool isSameExecutableProcess(const HANDLE processHandle)
            {
                wchar_t processPath[32768] = {};
                DWORD processPathCount = static_cast<DWORD>(ARRAYSIZE(processPath));
                if (::QueryFullProcessImageNameW(
                    processHandle,
                    0,
                    processPath,
                    &processPathCount) == FALSE)
                {
                    return false;
                }
                return _wcsicmp(processPath, gState.executablePath) == 0;
            }
        }

        void installCrashHandler(const Configuration& configuration)
        {
            if (gState.installed)
            {
                return;
            }
            gState.installed = true;
            gState.chinese = isChineseSystemUi();
            gState.preferLauncherReporter = configuration.preferLauncherReporter;
            copyText(
                gState.productName,
                ARRAYSIZE(gState.productName),
                configuration.productName == nullptr ? L"KswordARK" : configuration.productName);
            copyText(
                gState.dumpFilePrefix,
                ARRAYSIZE(gState.dumpFilePrefix),
                configuration.dumpFilePrefix == nullptr ? L"KswordARK" : configuration.dumpFilePrefix);
            gState.restartAlreadyAttempted = commandLineHasArgument(kCrashRestartedArgument);
            resolveExecutablePaths();
            (void)ensureCrashDirectory();
            gState.dbgHelpModule = ::LoadLibraryW(L"dbghelp.dll");
            if (gState.dbgHelpModule != nullptr)
            {
                gState.miniDumpWriteDump = reinterpret_cast<MiniDumpWriteDumpFunction>(
                    ::GetProcAddress(gState.dbgHelpModule, "MiniDumpWriteDump"));
            }
            initializeDefaultDialogText();
            ::SetUnhandledExceptionFilter(topLevelExceptionFilter);
        }

        void updateCrashDialogText(const DialogText& text)
        {
            if (text.title != nullptr) copyText(gState.title, ARRAYSIZE(gState.title), text.title);
            if (text.instruction != nullptr) copyText(gState.instruction, ARRAYSIZE(gState.instruction), text.instruction);
            if (text.exceptionCodeLabel != nullptr) copyText(gState.exceptionCodeLabel, ARRAYSIZE(gState.exceptionCodeLabel), text.exceptionCodeLabel);
            if (text.exceptionAddressLabel != nullptr) copyText(gState.exceptionAddressLabel, ARRAYSIZE(gState.exceptionAddressLabel), text.exceptionAddressLabel);
            if (text.dumpPathLabel != nullptr) copyText(gState.dumpPathLabel, ARRAYSIZE(gState.dumpPathLabel), text.dumpPathLabel);
            if (text.dumpUnavailableText != nullptr) copyText(gState.dumpUnavailableText, ARRAYSIZE(gState.dumpUnavailableText), text.dumpUnavailableText);
            if (text.restartQuestion != nullptr) copyText(gState.restartQuestion, ARRAYSIZE(gState.restartQuestion), text.restartQuestion);
            if (text.repeatedCrashText != nullptr) copyText(gState.repeatedCrashText, ARRAYSIZE(gState.repeatedCrashText), text.repeatedCrashText);
            if (text.restartFailedText != nullptr) copyText(gState.restartFailedText, ARRAYSIZE(gState.restartFailedText), text.restartFailedText);
        }

        bool commandLineHasArgument(const wchar_t* argumentName)
        {
            if (argumentName == nullptr || argumentName[0] == L'\0')
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
            for (int index = 1; index < argumentCount; ++index)
            {
                if (_wcsicmp(argumentVector[index], argumentName) == 0)
                {
                    found = true;
                    break;
                }
            }
            ::LocalFree(argumentVector);
            return found;
        }

        bool waitForCrashRestartTargetFromCommandLine(const DWORD timeoutMilliseconds)
        {
            unsigned long long processId = 0;
            if (!tryReadArgumentValue(kCrashRestartWaitPidArgument, &processId)
                || processId == 0
                || processId > static_cast<unsigned long long>(MAXDWORD))
            {
                return false;
            }

            const DWORD kPredecessorProcessId = static_cast<DWORD>(processId);
            HANDLE processHandle = ::OpenProcess(
                SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
                FALSE,
                kPredecessorProcessId);
            if (processHandle == nullptr)
            {
                return false;
            }
            if (!isCurrentProcessDirectChildOf(kPredecessorProcessId)
                || !isSameExecutableProcess(processHandle))
            {
                ::CloseHandle(processHandle);
                return false;
            }
            const DWORD kWaitResult = ::WaitForSingleObject(
                processHandle,
                timeoutMilliseconds);
            ::CloseHandle(processHandle);
            return kWaitResult == WAIT_OBJECT_0;
        }
    }
}

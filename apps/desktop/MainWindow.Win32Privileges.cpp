#include "MainWindow.h"

#include <QApplication>
#include <QCoreApplication>
#include <QStringList>
#pragma warning(disable: 4996)
#include "Framework.h"
#include "../../shared/crash/WinCrashHandler.h"
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <shellapi.h>
#include <sddl.h>
#include <winternl.h>

#include <algorithm>
#include <utility>
#include <vector>
#include <TlHelp32.h>

#include "MainWindow.DriverServiceBackendSupport.h"
#include "MainWindow.Win32PrivilegesSupport.h"

namespace ksword::ui::main_window
{
    QString formatWin32ErrorText(const DWORD errorCode)
    {
        if (errorCode == ERROR_SUCCESS)
        {
            return QStringLiteral("成功");
        }

        LPWSTR messageBuffer = nullptr;
        const DWORD kMessageLength = ::FormatMessageW(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            nullptr,
            errorCode,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            reinterpret_cast<LPWSTR>(&messageBuffer),
            0,
            nullptr);

        QString messageText;
        if (kMessageLength > 0 && messageBuffer != nullptr)
        {
            messageText = QString::fromWCharArray(messageBuffer, static_cast<int>(kMessageLength)).trimmed();
        }
        if (messageBuffer != nullptr)
        {
            ::LocalFree(messageBuffer);
        }
        if (messageText.isEmpty())
        {
            messageText = QStringLiteral("未知系统错误");
        }
        return messageText;
    }

    QString quoteWin32CommandLineArgument(const std::wstring& argumentText)
    {
        // argumentText usage: wrap the exe path into a command-line argument that CreateProcessAsUserW can safely parse.
        QString escapedText = QString::fromStdWString(argumentText);
        escapedText.replace(QStringLiteral("\""), QStringLiteral("\\\""));
        return QStringLiteral("\"%1\"").arg(escapedText);
    }

    // containsQtArgument:
    // - Input: argumentList is the QCoreApplication argument list; argumentText is the internal argument name.
    // - Processing: Skip the exe path and perform case-insensitive full argument matching.
    // - Returns: true if the argument already exists, otherwise returns false.
    bool containsQtArgument(const QStringList& argumentList, const QString& argumentText)
    {
        for (int index = 1; index < argumentList.size(); ++index)
        {
            if (QString::compare(argumentList.at(index), argumentText, Qt::CaseInsensitive) == 0)
            {
                return true;
            }
        }
        return false;
    }

    // argumentsWithPrivilegeRestartMarker:
    // - Input argumentList: current Qt arguments;
    // - Processing: Appends an internal marker parameter to the restart command for UIAccess/Admin privilege switching to prevent new instances from being directly blocked by anti-multiple-open checks.
    // - Returns: A list of arguments containing the internal marker; returns as-is if already present.
    QStringList argumentsWithPrivilegeRestartMarker(QStringList argumentList)
    {
        const QString kMarkerText = QString::fromWCharArray(kKswordPrivilegeRestartArgument);
        if (!containsQtArgument(argumentList, kMarkerText))
        {
            argumentList.push_back(kMarkerText);
        }
        return argumentList;
    }

    // argumentsWithPrivilegeRestartTakeover:
    // - Input argumentList: current Qt arguments; predecessorProcessId: PID of the old instance about to exit;
    // - Processing: Replace the wait PID potentially left over from an earlier restart and append parameters for this privilege switch takeover.
    // - Returns: A list of arguments for the new instance to wait for the parent process of the same executable to exit.
    QStringList argumentsWithPrivilegeRestartTakeover(
        QStringList argumentList,
        const DWORD predecessorProcessId)
    {
        argumentList = argumentsWithPrivilegeRestartMarker(std::move(argumentList));
        const QString kWaitPidArgument =
            QString::fromWCharArray(ks::crash::kCrashRestartWaitPidArgument);
        for (int index = 1; index < argumentList.size();)
        {
            if (QString::compare(
                    argumentList.at(index),
                    kWaitPidArgument,
                    Qt::CaseInsensitive) != 0)
            {
                ++index;
                continue;
            }

            argumentList.removeAt(index);
            if (index < argumentList.size())
            {
                bool isProcessId = false;
                (void)argumentList.at(index).toULongLong(&isProcessId);
                if (isProcessId)
                {
                    argumentList.removeAt(index);
                }
            }
        }
        argumentList.push_back(kWaitPidArgument);
        argumentList.push_back(QString::number(predecessorProcessId));
        return argumentList;
    }

    QString formatWin32StepFailure(const QString& stepText, const DWORD errorCode)
    {
        // stepText: Describes the failed API or stage to facilitate direct identification in UI and logs.
        return QStringLiteral("%1 失败，错误码：%2，系统信息：%3")
            .arg(stepText)
            .arg(errorCode)
            .arg(formatWin32ErrorText(errorCode));
    }

    QString privilegeNameToDisplayText(const wchar_t* const privilegeName)
    {
        // privilegeName: Converts Win32 privilege constants to QString for diagnostic output.
        if (privilegeName == nullptr || privilegeName[0] == L'\0')
        {
            return QStringLiteral("<empty>");
        }
        return QString::fromWCharArray(privilegeName);
    }

    bool enableTokenPrivilege(
        const HANDLE tokenHandle,
        const wchar_t* const privilegeName,
        DWORD* const errorCodeOut)
    {
        // errorCodeOut usage: Returns the failure reason for LookupPrivilegeValue/AdjustTokenPrivileges to the caller.
        if (errorCodeOut != nullptr)
        {
            *errorCodeOut = ERROR_SUCCESS;
        }
        if (tokenHandle == nullptr || privilegeName == nullptr || privilegeName[0] == L'\0')
        {
            if (errorCodeOut != nullptr)
            {
                *errorCodeOut = ERROR_INVALID_PARAMETER;
            }
            return false;
        }

        // privilegeLuid purpose: Resolves a privilege name to the corresponding LUID in the current system.
        LUID privilegeLuid{};
        if (::LookupPrivilegeValueW(nullptr, privilegeName, &privilegeLuid) == FALSE)
        {
            if (errorCodeOut != nullptr)
            {
                *errorCodeOut = ::GetLastError();
            }
            return false;
        }

        // tokenPrivileges usage: Enable only one target privilege without altering the state of other privileges.
        TOKEN_PRIVILEGES tokenPrivileges{};
        tokenPrivileges.PrivilegeCount = 1;
        tokenPrivileges.Privileges[0].Luid = privilegeLuid;
        tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        if (::AdjustTokenPrivileges(
            tokenHandle,
            FALSE,
            &tokenPrivileges,
            sizeof(tokenPrivileges),
            nullptr,
            nullptr) == FALSE)
        {
            if (errorCodeOut != nullptr)
            {
                *errorCodeOut = ::GetLastError();
            }
            return false;
        }

        const DWORD kAdjustError = ::GetLastError();
        if (kAdjustError != ERROR_SUCCESS)
        {
            if (errorCodeOut != nullptr)
            {
                *errorCodeOut = kAdjustError;
            }
            return false;
        }
        return true;
    }

    bool enableCurrentProcessPrivilege(const wchar_t* const privilegeName, DWORD* const errorCodeOut);

    QString tryEnableCurrentProcessPrivilegeForUiAccess(const wchar_t* const privilegeName)
    {
        // privilegeName: Specifies the current process privilege prepared for UIAccess fallback.
        DWORD privilegeError = ERROR_SUCCESS;
        const bool kEnableOk = enableCurrentProcessPrivilege(privilegeName, &privilegeError);
        if (kEnableOk)
        {
            return QStringLiteral("%1：已启用").arg(privilegeNameToDisplayText(privilegeName));
        }
        return QStringLiteral("%1：未启用（%2，%3）")
            .arg(privilegeNameToDisplayText(privilegeName))
            .arg(privilegeError)
            .arg(formatWin32ErrorText(privilegeError));
    }

    bool queryTokenSessionId(const HANDLE tokenHandle, DWORD* const sessionIdOut, DWORD* const errorCodeOut)
    {
        // sessionIdOut usage: Return the session to which the token belongs, determining whether the new process can display on the current interactive desktop.
        if (sessionIdOut != nullptr)
        {
            *sessionIdOut = 0;
        }
        if (errorCodeOut != nullptr)
        {
            *errorCodeOut = ERROR_SUCCESS;
        }
        if (tokenHandle == nullptr || sessionIdOut == nullptr)
        {
            if (errorCodeOut != nullptr)
            {
                *errorCodeOut = ERROR_INVALID_PARAMETER;
            }
            return false;
        }

        DWORD returnLength = 0;
        DWORD tokenSessionId = 0;
        if (::GetTokenInformation(
            tokenHandle,
            TokenSessionId,
            &tokenSessionId,
            sizeof(tokenSessionId),
            &returnLength) == FALSE)
        {
            if (errorCodeOut != nullptr)
            {
                *errorCodeOut = ::GetLastError();
            }
            return false;
        }

        *sessionIdOut = tokenSessionId;
        return true;
    }

    bool tokenBelongsToLocalSystem(const HANDLE tokenHandle, DWORD* const errorCodeOut)
    {
        // errorCodeOut usage: Retains the reason for query failure; returning false does not necessarily mean 'not SYSTEM'.
        if (errorCodeOut != nullptr)
        {
            *errorCodeOut = ERROR_SUCCESS;
        }
        if (tokenHandle == nullptr)
        {
            if (errorCodeOut != nullptr)
            {
                *errorCodeOut = ERROR_INVALID_HANDLE;
            }
            return false;
        }

        DWORD requiredLength = 0;
        ::GetTokenInformation(tokenHandle, TokenUser, nullptr, 0, &requiredLength);
        if (requiredLength == 0)
        {
            if (errorCodeOut != nullptr)
            {
                *errorCodeOut = ::GetLastError();
            }
            return false;
        }

        // userBuffer purpose: stores TOKEN_USER; variable-length structures must be held in a dynamic buffer.
        std::vector<BYTE> userBuffer(requiredLength, 0);
        if (::GetTokenInformation(
            tokenHandle,
            TokenUser,
            userBuffer.data(),
            requiredLength,
            &requiredLength) == FALSE)
        {
            if (errorCodeOut != nullptr)
            {
                *errorCodeOut = ::GetLastError();
            }
            return false;
        }

        BYTE systemSidBuffer[SECURITY_MAX_SID_SIZE] = {};
        DWORD systemSidLength = static_cast<DWORD>(std::size(systemSidBuffer));
        if (::CreateWellKnownSid(
            WinLocalSystemSid,
            nullptr,
            systemSidBuffer,
            &systemSidLength) == FALSE)
        {
            if (errorCodeOut != nullptr)
            {
                *errorCodeOut = ::GetLastError();
            }
            return false;
        }

        const TOKEN_USER* tokenUser = reinterpret_cast<const TOKEN_USER*>(userBuffer.data());
        return ::EqualSid(tokenUser->User.Sid, systemSidBuffer) != FALSE;
    }

    bool findSystemProcessTokenCandidate(
        const DWORD currentSessionId,
        DWORD* const processIdOut,
        QString* const processNameOut,
        DWORD* const processSessionIdOut,
        QString* const detailTextOut)
    {
        // processIdOut/processNameOut/processSessionIdOut purpose: Return the process most suitable as a source for the SYSTEM token.
        if (processIdOut != nullptr)
        {
            *processIdOut = 0;
        }
        if (processNameOut != nullptr)
        {
            processNameOut->clear();
        }
        if (processSessionIdOut != nullptr)
        {
            *processSessionIdOut = 0;
        }
        if (detailTextOut != nullptr)
        {
            detailTextOut->clear();
        }

        // candidateRank usage:
        // - 0 indicates not yet found.
        // - Higher values indicate higher priority; winlogon.exe within the same Session is optimal.
        int bestRank = 0;
        DWORD bestPid = 0;
        DWORD bestSessionId = 0;
        QString bestProcessName;

        ScopedHandle snapshotHandle(::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
        if (!snapshotHandle.isValid())
        {
            const DWORD kErrorCode = ::GetLastError();
            if (detailTextOut != nullptr)
            {
                *detailTextOut = formatWin32StepFailure(QStringLiteral("CreateToolhelp32Snapshot"), kErrorCode);
            }
            return false;
        }

        PROCESSENTRY32W processEntry{};
        processEntry.dwSize = sizeof(processEntry);
        if (::Process32FirstW(snapshotHandle.get(), &processEntry) == FALSE)
        {
            const DWORD kErrorCode = ::GetLastError();
            if (detailTextOut != nullptr)
            {
                *detailTextOut = formatWin32StepFailure(QStringLiteral("Process32FirstW"), kErrorCode);
            }
            return false;
        }

        do
        {
            // processSessionId: Prefer winlogon from the current interactive Session to reduce the chance of launching on a non-visible desktop.
            DWORD processSessionId = 0;
            if (::ProcessIdToSessionId(processEntry.th32ProcessID, &processSessionId) == FALSE)
            {
                processSessionId = 0;
            }

            int rank = 0;
            const bool kSameSession = processSessionId == currentSessionId;
            if (_wcsicmp(processEntry.szExeFile, L"winlogon.exe") == 0)
            {
                rank = kSameSession ? 40 : 30;
            }
            else if (_wcsicmp(processEntry.szExeFile, L"services.exe") == 0)
            {
                rank = kSameSession ? 20 : 10;
            }

            if (rank > bestRank)
            {
                bestRank = rank;
                bestPid = processEntry.th32ProcessID;
                bestSessionId = processSessionId;
                bestProcessName = QString::fromWCharArray(processEntry.szExeFile);
            }
        } while (::Process32NextW(snapshotHandle.get(), &processEntry) != FALSE);

        if (bestPid == 0)
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = QStringLiteral("没有找到可用的 SYSTEM 令牌源进程（优先 winlogon.exe，其次 services.exe）。");
            }
            return false;
        }

        if (processIdOut != nullptr)
        {
            *processIdOut = bestPid;
        }
        if (processNameOut != nullptr)
        {
            *processNameOut = bestProcessName;
        }
        if (processSessionIdOut != nullptr)
        {
            *processSessionIdOut = bestSessionId;
        }
        return true;
    }

    // findExplorerProcessInSession:
    // - Input currentSessionId: Current interactive session.
    // - Processing: Iterate process snapshots to find explorer.exe in the same session;
    // - Returns: true if a valid candidate is found, with PID/process name output.
    bool findExplorerProcessInSession(
        const DWORD currentSessionId,
        DWORD* const processIdOut,
        QString* const processNameOut,
        QString* const detailTextOut)
    {
        if (processIdOut != nullptr)
        {
            *processIdOut = 0;
        }
        if (processNameOut != nullptr)
        {
            processNameOut->clear();
        }
        if (detailTextOut != nullptr)
        {
            detailTextOut->clear();
        }

        ScopedHandle snapshotHandle(::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
        if (!snapshotHandle.isValid())
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = formatWin32StepFailure(QStringLiteral("CreateToolhelp32Snapshot"), ::GetLastError());
            }
            return false;
        }

        PROCESSENTRY32W processEntry{};
        processEntry.dwSize = sizeof(processEntry);
        if (::Process32FirstW(snapshotHandle.get(), &processEntry) == FALSE)
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = formatWin32StepFailure(QStringLiteral("Process32FirstW"), ::GetLastError());
            }
            return false;
        }

        do
        {
            DWORD processSessionId = 0;
            if (::ProcessIdToSessionId(processEntry.th32ProcessID, &processSessionId) == FALSE)
            {
                continue;
            }
            if (processSessionId != currentSessionId)
            {
                continue;
            }
            if (_wcsicmp(processEntry.szExeFile, L"explorer.exe") != 0)
            {
                continue;
            }

            if (processIdOut != nullptr)
            {
                *processIdOut = processEntry.th32ProcessID;
            }
            if (processNameOut != nullptr)
            {
                *processNameOut = QString::fromWCharArray(processEntry.szExeFile);
            }
            return true;
        } while (::Process32NextW(snapshotHandle.get(), &processEntry) != FALSE);

        if (detailTextOut != nullptr)
        {
            *detailTextOut = QStringLiteral("当前 Session 未找到 explorer.exe。");
        }
        return false;
    }

    // quoteQStringCommandLineArgument:
    // - Input argumentText: Qt string argument;
    // - Processing: Wrap double quotes with minimal Win32 command-line escaping.
    // - Return: Argument fragment suitable for concatenation into a CreateProcessAsUserW commandLine.
    QString quoteQStringCommandLineArgument(QString argumentText)
    {
        argumentText.replace(QStringLiteral("\""), QStringLiteral("\\\""));
        return QStringLiteral("\"%1\"").arg(argumentText);
    }

    // launchSelfAsUnelevatedFromExplorer:
    // - Input argumentList: Current QApplication argument list;
    // - Processing: Launch self using the primary token of the explorer.exe in the same session, transitioning from UIAccess/SYSTEM back to a standard user mode.
    // - Return: true indicates a normal instance has been created; false indicates the caller can fall back to ShellExecute.
    bool launchSelfAsUnelevatedFromExplorer(const QStringList& argumentList, QString* detailTextOut)
    {
        if (detailTextOut != nullptr)
        {
            detailTextOut->clear();
        }

        wchar_t executablePathBuffer[MAX_PATH] = {};
        const DWORD kExecutablePathLength = ::GetModuleFileNameW(nullptr, executablePathBuffer, MAX_PATH);
        if (kExecutablePathLength == 0 || kExecutablePathLength >= MAX_PATH)
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = formatWin32StepFailure(QStringLiteral("GetModuleFileNameW"), ::GetLastError());
            }
            return false;
        }

        DWORD currentSessionId = 0;
        if (::ProcessIdToSessionId(::GetCurrentProcessId(), &currentSessionId) == FALSE)
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = formatWin32StepFailure(QStringLiteral("ProcessIdToSessionId"), ::GetLastError());
            }
            return false;
        }

        DWORD explorerPid = 0;
        QString explorerName;
        QString findDetailText;
        if (!findExplorerProcessInSession(currentSessionId, &explorerPid, &explorerName, &findDetailText))
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = findDetailText;
            }
            return false;
        }

        ScopedHandle explorerProcessHandle(::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, explorerPid));
        if (!explorerProcessHandle.isValid())
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = formatWin32StepFailure(QStringLiteral("OpenProcess(%1)").arg(explorerName), ::GetLastError());
            }
            return false;
        }

        HANDLE rawExplorerTokenHandle = nullptr;
        if (::OpenProcessToken(explorerProcessHandle.get(), TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &rawExplorerTokenHandle) == FALSE)
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = formatWin32StepFailure(QStringLiteral("OpenProcessToken(%1)").arg(explorerName), ::GetLastError());
            }
            return false;
        }
        ScopedHandle explorerTokenHandle(rawExplorerTokenHandle);

        SECURITY_ATTRIBUTES securityAttributes{};
        securityAttributes.nLength = sizeof(securityAttributes);
        HANDLE rawPrimaryTokenHandle = nullptr;
        if (::DuplicateTokenEx(
            explorerTokenHandle.get(),
            MAXIMUM_ALLOWED,
            &securityAttributes,
            SecurityImpersonation,
            TokenPrimary,
            &rawPrimaryTokenHandle) == FALSE)
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = formatWin32StepFailure(QStringLiteral("DuplicateTokenEx(explorer)"), ::GetLastError());
            }
            return false;
        }
        ScopedHandle primaryTokenHandle(rawPrimaryTokenHandle);

        const QStringList kLaunchArgumentList = argumentsWithPrivilegeRestartMarker(argumentList);
        QString commandLineText = quoteQStringCommandLineArgument(QString::fromWCharArray(executablePathBuffer));
        for (int index = 1; index < kLaunchArgumentList.size(); ++index)
        {
            commandLineText += QLatin1Char(' ');
            commandLineText += quoteQStringCommandLineArgument(kLaunchArgumentList.at(index));
        }

        std::wstring mutableCommandLine = commandLineText.toStdWString();
        STARTUPINFOW startupInfo{};
        startupInfo.cb = sizeof(startupInfo);
        PROCESS_INFORMATION processInfo{};
        const BOOL kCreateOk = ::CreateProcessAsUserW(
            primaryTokenHandle.get(),
            nullptr,
            mutableCommandLine.data(),
            nullptr,
            nullptr,
            FALSE,
            0,
            nullptr,
            nullptr,
            &startupInfo,
            &processInfo);
        if (kCreateOk == FALSE)
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = formatWin32StepFailure(QStringLiteral("CreateProcessAsUserW(explorer token)"), ::GetLastError());
            }
            return false;
        }

        if (processInfo.hThread != nullptr)
        {
            ::CloseHandle(processInfo.hThread);
        }
        if (processInfo.hProcess != nullptr)
        {
            ::CloseHandle(processInfo.hProcess);
        }

        if (detailTextOut != nullptr)
        {
            *detailTextOut = QStringLiteral("已通过 explorer.exe 普通用户令牌启动新实例，PID=%1。").arg(processInfo.dwProcessId);
        }
        return true;
    }
}

using namespace ksword::ui::main_window;

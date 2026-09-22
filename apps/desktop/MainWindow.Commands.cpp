#include "MainWindow.h"
#include "internationalization/LanguageManager.h"

#include <QDir>
#include <QFileInfo>
#include <QMessageBox>
#pragma warning(disable: 4996)
#include "Framework.h"
#include "ui/CommandExecutionPopup.h"
#include "../../shared/platform/process/Process.h"
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <shellapi.h>
#include <sddl.h>
#include <winternl.h>

#include <algorithm>
#include <TlHelp32.h>

void MainWindow::executeCommandInNewConsole(const QString& commandText)
{
    // The default entry preserves the original behavior of 'Enter to directly open visible CMD'; if a popup exists, use the user's last selection.
    ks::ui::CommandExecutionOptions options;
    options.workingDirectory = QDir::currentPath();
    if (commandExecutionPopup_ != nullptr)
    {
        options = commandExecutionPopup_->currentOptions();
    }
    executeCommandWithOptions(commandText, options);
}

void MainWindow::executeCommandWithOptions(
    const QString& commandText,
    const ks::ui::CommandExecutionOptions& options)
{
    const QString kTrimmedCommandText = commandText.trimmed();
    if (kTrimmedCommandText.isEmpty())
    {
        return;
    }

    // workingDirectoryText purpose: normalize the dialog input into a directory acceptable to CreateProcess.
    QString workingDirectoryText = options.workingDirectory.trimmed();
    if (workingDirectoryText.isEmpty())
    {
        workingDirectoryText = QDir::currentPath();
    }
    workingDirectoryText = QDir::toNativeSeparators(workingDirectoryText);
    const QFileInfo kWorkingDirectoryInfo(workingDirectoryText);
    if (!kWorkingDirectoryInfo.isDir())
    {
        QMessageBox::warning(
            this,
            ks::i18n::text(QStringLiteral("cmd.popup.directory.invalid.title"), QStringLiteral("执行目录无效")),
            ks::i18n::text(
                QStringLiteral("cmd.popup.directory.invalid.message"),
                QStringLiteral("目录不存在或不可访问：%1"))
                .arg(workingDirectoryText));
        return;
    }

    if (options.userMode == ks::ui::CommandExecutionOptions::UserMode::kProcessToken
        && options.tokenSourcePid == 0U)
    {
        QMessageBox::warning(
            this,
            ks::i18n::text(QStringLiteral("cmd.popup.token.invalid.title"), QStringLiteral("令牌 PID 无效")),
            ks::i18n::text(
                QStringLiteral("cmd.popup.token.invalid.message"),
                QStringLiteral("请输入有效的进程 PID。")));
        return;
    }

    // SYSTEM user has higher privileges: the execution entry point requires unified re-confirmation to prevent bypassing the confirmation dialog via direct signal connections.
    if (options.userMode == ks::ui::CommandExecutionOptions::UserMode::kSystem)
    {
        const QMessageBox::StandardButton kAnswer = QMessageBox::question(
            this,
            ks::i18n::text(QStringLiteral("cmd.popup.system.confirm.title"), QStringLiteral("确认 SYSTEM 用户")),
            ks::i18n::text(
                QStringLiteral("cmd.popup.system.confirm.message"),
                QStringLiteral("即将以 SYSTEM 用户执行命令，命令可能访问当前用户无法访问的系统资源。\n\n是否继续？")),
            QMessageBox::Yes | QMessageBox::No,
            QMessageBox::No);
        if (kAnswer != QMessageBox::Yes)
        {
            return;
        }
    }

    KLogEvent commandEvent;
    info << commandEvent
        << "[MainWindow] 标题栏命令执行请求, command="
        << kTrimmedCommandText.toStdString()
        << eol;

    // commandInterpreterPath: Uses the system ComSpec to prevent hijacking of the command interpreter by a file with the same name in the distribution package directory.
    QString commandInterpreterPath = qEnvironmentVariable("ComSpec").trimmed();
    if (commandInterpreterPath.isEmpty())
    {
        commandInterpreterPath = QStringLiteral("C:\\Windows\\System32\\cmd.exe");
    }
    commandInterpreterPath = QDir::toNativeSeparators(commandInterpreterPath);

    // commandSwitchText purpose: Use /K to keep interactive for visible windows, use /C to execute and exit for background mode.
    const QString kCommandSwitchText = options.openConsoleWindow
        ? QStringLiteral("/K")
        : QStringLiteral("/C");
    const QString kCommandLineText = QStringLiteral("\"%1\" %2 %3")
        .arg(commandInterpreterPath)
        .arg(kCommandSwitchText)
        .arg(kTrimmedCommandText);

    // The administrator option triggers standard UAC via the 'runas' verb in ShellExecuteEx, without forging or bypassing security boundaries.
    const bool kCurrentUserSelected = options.userMode
        == ks::ui::CommandExecutionOptions::UserMode::kCurrentUser;
    const bool kAdministratorRequested = options.privilegeMode
        == ks::ui::CommandExecutionOptions::PrivilegeMode::kAdministrator;
    if (kCurrentUserSelected && kAdministratorRequested && !hasAdminPrivilege())
    {
        const std::wstring kCommandInterpreterPathWide = commandInterpreterPath.toStdWString();
        const std::wstring kCommandParametersWide =
            (kCommandSwitchText + QStringLiteral(" ") + kTrimmedCommandText).toStdWString();
        const std::wstring kWorkingDirectoryWide = workingDirectoryText.toStdWString();

        SHELLEXECUTEINFOW shellExecuteInfo{};
        shellExecuteInfo.cbSize = sizeof(shellExecuteInfo);
        shellExecuteInfo.fMask = SEE_MASK_NOCLOSEPROCESS;
        shellExecuteInfo.lpVerb = L"runas";
        shellExecuteInfo.lpFile = kCommandInterpreterPathWide.c_str();
        shellExecuteInfo.lpParameters = kCommandParametersWide.c_str();
        shellExecuteInfo.lpDirectory = kWorkingDirectoryWide.c_str();
        shellExecuteInfo.nShow = options.openConsoleWindow ? SW_SHOWNORMAL : SW_HIDE;

        if (::ShellExecuteExW(&shellExecuteInfo) == FALSE)
        {
            const DWORD kErrorCode = ::GetLastError();
            err << commandEvent
                << "[MainWindow] 标题栏命令执行失败, errorCode="
                << kErrorCode
                << eol;
            QMessageBox::warning(
                this,
                ks::i18n::text(QStringLiteral("cmd.popup.execute_failed.title"), QStringLiteral("执行命令失败")),
                ks::i18n::text(
                    QStringLiteral("cmd.popup.execute_failed.message"),
                    QStringLiteral("无法启动 cmd.exe。\n错误码：%1\n%2"))
                    .arg(kErrorCode)
                    .arg(QStringLiteral("UAC 可能已取消。")));
            return;
        }

        const DWORD kProcessId = shellExecuteInfo.hProcess != nullptr
            ? ::GetProcessId(shellExecuteInfo.hProcess)
            : 0U;
        if (shellExecuteInfo.hProcess != nullptr)
        {
            ::CloseHandle(shellExecuteInfo.hProcess);
        }
        info << commandEvent
            << "[MainWindow] 标题栏命令执行已启动, pid="
            << kProcessId
            << eol;
        return;
    }

    // tokenSourcePid purpose: Records the source PID for SYSTEM, a specified process, or a standard Shell when selecting the token mode.
    DWORD tokenSourcePid = 0U;
    if (options.userMode == ks::ui::CommandExecutionOptions::UserMode::kSystem)
    {
        tokenSourcePid = 4U;
    }
    else if (options.userMode == ks::ui::CommandExecutionOptions::UserMode::kProcessToken)
    {
        tokenSourcePid = options.tokenSourcePid;
    }
    else if (options.privilegeMode
        == ks::ui::CommandExecutionOptions::PrivilegeMode::kStandard
        && hasAdminPrivilege())
    {
        // Elevated instances revert to standard user privileges using the Explorer token; standard instances are created directly to maintain standard permissions.
        DWORD shellProcessId = 0U;
        const HWND kShellWindow = ::GetShellWindow();
        if (kShellWindow != nullptr)
        {
            ::GetWindowThreadProcessId(kShellWindow, &shellProcessId);
        }
        if (shellProcessId == 0U)
        {
            const DWORD kErrorCode = ERROR_NOT_FOUND;
            err << commandEvent
                << "[MainWindow] 标题栏命令执行失败, errorCode="
                << kErrorCode
                << eol;
            QMessageBox::warning(
                this,
                ks::i18n::text(QStringLiteral("cmd.popup.execute_failed.title"), QStringLiteral("执行命令失败")),
                ks::i18n::text(
                    QStringLiteral("cmd.popup.execute_failed.message"),
                    QStringLiteral("无法启动 cmd.exe。\n错误码：%1\n%2"))
                    .arg(kErrorCode)
                    .arg(QStringLiteral("未找到交互式 Shell 进程，无法获取普通用户令牌。")));
            return;
        }
        tokenSourcePid = shellProcessId;
    }

    ks::process::CreateProcessRequest request;
    request.useApplicationName = true;
    request.applicationName = commandInterpreterPath.toStdString();
    request.useCommandLine = true;
    request.commandLine = kCommandLineText.toStdString();
    request.creationFlags = (options.openConsoleWindow ? CREATE_NEW_CONSOLE : CREATE_NO_WINDOW)
        | CREATE_UNICODE_ENVIRONMENT;
    request.useCurrentDirectory = true;
    request.currentDirectory = workingDirectoryText.toStdString();
    request.startupInfo.useValue = true;
    request.startupInfo.dwFlags = STARTF_USESHOWWINDOW;
    request.startupInfo.wShowWindow = static_cast<std::uint16_t>(
        options.openConsoleWindow ? SW_SHOWNORMAL : SW_HIDE);
    request.tokenModeEnabled = tokenSourcePid != 0U;
    request.tokenSourcePid = tokenSourcePid;

    ks::process::CreateProcessResult result;
    if (!ks::process::launchProcess(request, &result))
    {
        const DWORD kErrorCode = result.win32Error != 0U
            ? static_cast<DWORD>(result.win32Error)
            : ERROR_GEN_FAILURE;
        err << commandEvent
            << "[MainWindow] 标题栏命令执行失败, errorCode="
            << kErrorCode
            << eol;
        QMessageBox::warning(
            this,
            ks::i18n::text(QStringLiteral("cmd.popup.execute_failed.title"), QStringLiteral("执行命令失败")),
            ks::i18n::text(
                QStringLiteral("cmd.popup.execute_failed.message"),
                QStringLiteral("无法启动 cmd.exe。\n错误码：%1\n%2"))
                .arg(kErrorCode)
                .arg(QString::fromStdString(result.detailText)));
        return;
    }

    info << commandEvent
        << "[MainWindow] 标题栏命令执行已启动, pid="
        << result.dwProcessId
        << eol;
}

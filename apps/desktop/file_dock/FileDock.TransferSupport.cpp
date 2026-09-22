#include "FileDock.Support.h"

namespace ksword::ui::file_dock
{
    // Recursively copy directories: used for cross-panel directory copy scenarios.
    bool copyDirectoryRecursively(const QString& sourcePath, const QString& targetPath, QString& errorTextOut)
    {
        if (isPathReparsePoint(sourcePath))
        {
            errorTextOut = ks::i18n::displayText(QStringLiteral("为避免越界递归，不复制符号链接或重解析点: %1"))
                .arg(QDir::toNativeSeparators(sourcePath));
            return false;
        }

        QDir sourceDir(sourcePath);
        if (!sourceDir.exists())
        {
            errorTextOut = QStringLiteral("源目录不存在: %1").arg(sourcePath);
            return false;
        }

        QDir targetDir;
        if (!targetDir.mkpath(targetPath))
        {
            errorTextOut = QStringLiteral("创建目标目录失败: %1").arg(targetPath);
            return false;
        }

        const QFileInfoList kEntries = sourceDir.entryInfoList(
            QDir::NoDotAndDotDot | QDir::AllEntries | QDir::Hidden | QDir::System);
        for (const QFileInfo& info : kEntries)
        {
            const QString kSrc = info.absoluteFilePath();
            const QString kDst = QDir(targetPath).filePath(info.fileName());

            if (info.isSymLink() || isPathReparsePoint(kSrc))
            {
                errorTextOut = ks::i18n::displayText(QStringLiteral("为避免越界递归，不复制符号链接或重解析点: %1"))
                    .arg(QDir::toNativeSeparators(kSrc));
                return false;
            }

            if (info.isDir())
            {
                if (!copyDirectoryRecursively(kSrc, kDst, errorTextOut))
                {
                    return false;
                }
            }
            else
            {
                if (!QFile::copy(kSrc, kDst))
                {
                    errorTextOut = QStringLiteral("复制文件失败: %1 -> %2").arg(kSrc, kDst);
                    return false;
                }
            }
        }

        return true;
    }

    // copyFileTransactionally: Write to a temporary file in the same directory first, then replace the target only after the write is fully committed; on failure, preserve the original target.
    bool copyFileTransactionally(const QString& sourcePath, const QString& targetPath, QString& errorTextOut)
    {
        QFile sourceFile(sourcePath);
        if (!sourceFile.open(QIODevice::ReadOnly))
        {
            errorTextOut = ks::i18n::displayText(QStringLiteral("打开源文件失败: %1 (%2)"))
                .arg(sourcePath, sourceFile.errorString());
            return false;
        }

        QSaveFile targetFile(targetPath);
        // Disable direct-write fallback to prevent truncating the existing target file if temporary file creation fails.
        targetFile.setDirectWriteFallback(false);
        if (!targetFile.open(QIODevice::WriteOnly))
        {
            errorTextOut = ks::i18n::displayText(QStringLiteral("创建目标临时文件失败: %1 (%2)"))
                .arg(targetPath, targetFile.errorString());
            return false;
        }

        QByteArray copyBuffer(1024 * 1024, Qt::Uninitialized);
        while (true)
        {
            const qint64 kBytesRead = sourceFile.read(copyBuffer.data(), copyBuffer.size());
            if (kBytesRead < 0)
            {
                targetFile.cancelWriting();
                errorTextOut = ks::i18n::displayText(QStringLiteral("读取源文件失败: %1 (%2)"))
                    .arg(sourcePath, sourceFile.errorString());
                return false;
            }
            if (kBytesRead == 0)
            {
                break;
            }
            if (targetFile.write(copyBuffer.data(), kBytesRead) != kBytesRead)
            {
                targetFile.cancelWriting();
                errorTextOut = ks::i18n::displayText(QStringLiteral("写入目标临时文件失败: %1 (%2)"))
                    .arg(targetPath, targetFile.errorString());
                return false;
            }
        }

        targetFile.setPermissions(QFileInfo(sourcePath).permissions());
        if (!targetFile.commit())
        {
            errorTextOut = ks::i18n::displayText(QStringLiteral("提交目标文件失败: %1 (%2)"))
                .arg(targetPath, targetFile.errorString());
            return false;
        }
        return true;
    }

    // uniqueSiblingTransactionPath: Generates a temporary path on the same volume for directory replacement to ensure rename rollback.
    QString uniqueSiblingTransactionPath(const QString& targetPath, const QString& roleText)
    {
        const QFileInfo kTargetInfo(targetPath);
        const QString kTransactionName = QStringLiteral("-ksword-%1-%2-%3")
            .arg(
                roleText,
                kTargetInfo.fileName(),
                QUuid::createUuid().toString(QUuid::WithoutBraces));
        return kTargetInfo.dir().filePath(kTransactionName);
    }

    // removeTransactionPath purpose: Cleans up files or directories created by this transaction, without following other target paths.
    bool removeTransactionPath(const QString& path)
    {
        const QFileInfo kPathInfo(path);
        if (!kPathInfo.exists() && !kPathInfo.isSymLink())
        {
            return true;
        }
        if (kPathInfo.isDir() && !kPathInfo.isSymLink())
        {
            return QDir(path).removeRecursively();
        }
        return QFile::remove(path);
    }

    // copyDirectoryTransactionally purpose: Performs a full copy to a sibling staging directory, then replaces the target directory using a backup-based rollback mechanism.
    bool copyDirectoryTransactionally(const QString& sourcePath, const QString& targetPath, QString& errorTextOut)
    {
        const QString kStagingPath = uniqueSiblingTransactionPath(targetPath, QStringLiteral("staging"));
        const QString kBackupPath = uniqueSiblingTransactionPath(targetPath, QStringLiteral("backup"));
        const bool kTargetExisted = QFileInfo::exists(targetPath);

        if (!copyDirectoryRecursively(sourcePath, kStagingPath, errorTextOut))
        {
            removeTransactionPath(kStagingPath);
            return false;
        }

        QDir renameDir;
        if (kTargetExisted && !renameDir.rename(targetPath, kBackupPath))
        {
            removeTransactionPath(kStagingPath);
            errorTextOut = ks::i18n::displayText(QStringLiteral("备份现有目标目录失败: %1 -> %2"))
                .arg(targetPath, kBackupPath);
            return false;
        }

        if (!renameDir.rename(kStagingPath, targetPath))
        {
            const bool kRollbackOk = !kTargetExisted || renameDir.rename(kBackupPath, targetPath);
            removeTransactionPath(kStagingPath);
            errorTextOut = kRollbackOk
                ? ks::i18n::displayText(QStringLiteral("提交目标目录失败，旧目标已恢复: %1")).arg(targetPath)
                : ks::i18n::displayText(QStringLiteral("提交目标目录失败且旧目标恢复失败: %1，备份位于 %2"))
                    .arg(targetPath, kBackupPath);
            return false;
        }

        if (kTargetExisted && !removeTransactionPath(kBackupPath))
        {
            errorTextOut = ks::i18n::displayText(QStringLiteral("目录已替换，但旧目标备份清理失败: %1"))
                .arg(kBackupPath);
            return false;
        }
        return true;
    }

    // runCommandCaptureText：
    // - Purpose: Synchronously execute a cmd command and return the merged text of standard output and error output.
    // - Parameter commandText: The command string to execute after cmd /C.
    // - Parameter outputTextOut: Returns the execution output text for error messages.
    // - Parameter exitCodeOut: Returns the process exit code, used by the caller to determine success/failure.
    bool runCommandCaptureText(const QString& commandText, QString& outputTextOut, int& exitCodeOut)
    {
        QProcess process;
        process.setProgram(QStringLiteral("cmd.exe"));
        process.setArguments(QStringList{ QStringLiteral("/C"), commandText });
        process.start();
        process.waitForFinished(-1);

        const QByteArray kStdOutBytes = process.readAllStandardOutput();
        const QByteArray kStdErrBytes = process.readAllStandardError();
        outputTextOut = QString::fromLocal8Bit(kStdOutBytes + kStdErrBytes).trimmed();
        exitCodeOut = process.exitCode();
        return process.exitStatus() == QProcess::NormalExit && process.exitCode() == 0;
    }

    // openCommandPromptInDirectory：
    // - Purpose: Explicitly create a new console cmd.exe using Win32 CreateProcessW and set the working directory to the target path;
    // - Parameter workPath: Folder path to use as the current directory for cmd; converted to Windows native separators.
    // - Parameter errorCodeOut: returns GetLastError if CreateProcessW fails, or ERROR_SUCCESS on success;
    // - Returns: true if the cmd process was created; false if creation failed.
    bool openCommandPromptInDirectory(const QString& workPath, DWORD* const errorCodeOut)
    {
        if (errorCodeOut != nullptr)
        {
            *errorCodeOut = ERROR_SUCCESS;
        }

        const QString kNativeWorkPath = QDir::toNativeSeparators(workPath);
        std::wstring commandLineText = L"cmd.exe /K";
        std::wstring currentDirectoryText = kNativeWorkPath.toStdWString();
        if (currentDirectoryText.empty())
        {
            currentDirectoryText = QDir::toNativeSeparators(QDir::homePath()).toStdWString();
        }

        STARTUPINFOW startupInfo{};
        startupInfo.cb = sizeof(startupInfo);
        PROCESS_INFORMATION processInfo{};

        const BOOL kCreateOk = ::CreateProcessW(
            nullptr,
            commandLineText.data(),
            nullptr,
            nullptr,
            FALSE,
            CREATE_NEW_CONSOLE,
            nullptr,
            currentDirectoryText.c_str(),
            &startupInfo,
            &processInfo);
        if (kCreateOk == FALSE)
        {
            if (errorCodeOut != nullptr)
            {
                *errorCodeOut = ::GetLastError();
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
        return true;
    }

    // takeOwnershipBySystemCommand：
    // - Purpose: Execute takeown and icacls on the target path to acquire ownership and grant the Administrators group full control.
    // - Parameter targetPath: The file or directory path to be processed.
    // - Parameter detailTextOut: output step details (used for prompts on failure).
    // - Returns: true if all steps succeed.
    bool takeOwnershipBySystemCommand(const QString& targetPath, QString& detailTextOut)
    {
        const QFileInfo kInfo(targetPath);
        const QString kQuotedPath = QStringLiteral("\"%1\"").arg(QDir::toNativeSeparators(targetPath));
        const QString kTakeOwnCommand = kInfo.isDir()
            ? QStringLiteral("takeown /F %1 /A /R /D Y").arg(kQuotedPath)
            : QStringLiteral("takeown /F %1 /A").arg(kQuotedPath);
        const QString kGrantCommand = kInfo.isDir()
            ? QStringLiteral("icacls %1 /grant *S-1-5-32-544:F /T /C").arg(kQuotedPath)
            : QStringLiteral("icacls %1 /grant *S-1-5-32-544:F /C").arg(kQuotedPath);

        QString firstOutput;
        int firstExitCode = -1;
        const bool kTakeOwnOk = runCommandCaptureText(kTakeOwnCommand, firstOutput, firstExitCode);

        QString secondOutput;
        int secondExitCode = -1;
        const bool kGrantOk = runCommandCaptureText(kGrantCommand, secondOutput, secondExitCode);

        detailTextOut = QStringLiteral(
            "目标: %1\n"
            "takeown命令: %2\n"
            "takeown退出码: %3\n"
            "takeown输出:\n%4\n\n"
            "icacls命令: %5\n"
            "icacls退出码: %6\n"
            "icacls输出:\n%7")
            .arg(QDir::toNativeSeparators(targetPath))
            .arg(kTakeOwnCommand)
            .arg(firstExitCode)
            .arg(firstOutput.isEmpty() ? QStringLiteral("<无输出>") : firstOutput)
            .arg(kGrantCommand)
            .arg(secondExitCode)
            .arg(secondOutput.isEmpty() ? QStringLiteral("<无输出>") : secondOutput);
        return kTakeOwnOk && kGrantOk;
    }
}

#include "FileDock.Support.h"

namespace ksword::ui::file_dock
{
    // appendDriverDeleteTargetsPostOrder：
    // - Purpose: Expand a directory into a post-order list where child items are deleted before their parent directories.
    // - Note: Reparse point directories are not recursed into; only the link itself is deleted.
    // - repairPermissionBeforeEnumerate: Dedicated to forced deletion. When a directory's DACL denies enumeration,
    //   entryInfoList returns an empty list. expanding results would then treat non-empty directories as empty, causing
    //   subsequent deletion to fail. Therefore, ownership must be taken and permissions granted before enumerating each level.
    bool appendDriverDeleteTargetsPostOrder(
        const QString& rootPath,
        std::vector<DriverDeleteTarget>& targetsOut,
        QString& errorTextOut,
        const bool repairPermissionBeforeEnumerate )
    {
        const QFileInfo kRootInfo(rootPath);
        const bool kRootExists = kRootInfo.exists() || kRootInfo.isSymLink();
        if (!kRootExists)
        {
            errorTextOut = QStringLiteral("路径不存在：%1").arg(QDir::toNativeSeparators(rootPath));
            return false;
        }

        const bool kIsDirectory = kRootInfo.isDir();
        const bool kIsReparsePoint = isPathReparsePoint(rootPath);
        if (kIsDirectory && !kIsReparsePoint)
        {
            if (repairPermissionBeforeEnumerate)
            {
                QString repairDetailText;
                (void)takeOwnershipAndGrantFullControl(rootPath, true, &repairDetailText);
                (void)clearDeleteBlockingAttributes(rootPath);
            }

            const QFileInfoList kChildInfoList = QDir(rootPath).entryInfoList(
                QDir::NoDotAndDotDot | QDir::AllEntries | QDir::Hidden | QDir::System,
                QDir::DirsFirst | QDir::Name);
            for (const QFileInfo& childInfo : kChildInfoList)
            {
                if (!appendDriverDeleteTargetsPostOrder(
                        childInfo.absoluteFilePath(),
                        targetsOut,
                        errorTextOut,
                        repairPermissionBeforeEnumerate))
                {
                    return false;
                }
            }
        }

        targetsOut.push_back(DriverDeleteTarget{ rootPath, kIsDirectory });
        return true;
    }

    // clearDeleteBlockingAttributes：
    // - Purpose: Clear Read-only, Hidden, and System attributes, as these three will directly cause DeleteFileW/RemoveDirectoryW to fail.
    // - Returns: true indicates the attributes are deletable (being already normal counts as success).
    bool clearDeleteBlockingAttributes(const QString& path)
    {
        const std::wstring kNativePath = QDir::toNativeSeparators(path).toStdWString();
        const DWORD kAttributes = ::GetFileAttributesW(kNativePath.c_str());
        if (kAttributes == INVALID_FILE_ATTRIBUTES)
        {
            return false;
        }

        constexpr DWORD kBlockingAttributes =
            FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM;
        if ((kAttributes & kBlockingAttributes) == 0U)
        {
            return true;
        }

        DWORD newAttributes = kAttributes & ~kBlockingAttributes;
        if (newAttributes == 0U)
        {
            newAttributes = FILE_ATTRIBUTE_NORMAL;
        }
        return ::SetFileAttributesW(kNativePath.c_str(), newAttributes) != FALSE;
    }

    // allocateBuiltinAdministratorsSid：
    // - Purpose: Construct the BUILTIN\Administrators (S-1-5-32-544) SID; the caller must free it using LocalFree.
    PSID allocateBuiltinAdministratorsSid()
    {
        PSID administratorsSid = nullptr;
        if (::ConvertStringSidToSidW(L"S-1-5-32-544", &administratorsSid) == FALSE)
        {
            return nullptr;
        }
        return administratorsSid;
    }

    // takeOwnershipAndGrantFullControl：
    // - Purpose: Change the target's owner to BUILTIN\Administrators and append a full control ACE.
    // - Note: This is the permission mechanism for 'force delete' and R3 fallback retry; it does not alter file content.
    // - Return: Win32 error code; ERROR_SUCCESS indicates that both ownership and DACL have been written.
    DWORD takeOwnershipAndGrantFullControl(
        const QString& path,
        const bool isDirectory,
        QString* const detailTextOut)
    {
        // Taking ownership requires SeTakeOwnershipPrivilege. Setting the owner to Administrators instead of the
        // current account requires SeRestorePrivilege. Both privileges exist only in an administrator token.
        (void)enableFileContextPrivilege(SE_TAKE_OWNERSHIP_NAME);
        (void)enableFileContextPrivilege(SE_RESTORE_NAME);
        (void)enableFileContextPrivilege(SE_BACKUP_NAME);
        (void)enableFileContextPrivilege(SE_SECURITY_NAME);

        PSID administratorsSid = allocateBuiltinAdministratorsSid();
        if (administratorsSid == nullptr)
        {
            const DWORD kSidError = ::GetLastError();
            if (detailTextOut != nullptr)
            {
                *detailTextOut = formatFileWin32Error(QStringLiteral("ConvertStringSidToSidW(S-1-5-32-544)"), kSidError);
            }
            return kSidError == ERROR_SUCCESS ? ERROR_INVALID_PARAMETER : kSidError;
        }

        std::wstring nativePath = QDir::toNativeSeparators(path).toStdWString();
        DWORD ownerResult = ::SetNamedSecurityInfoW(
            nativePath.data(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            administratorsSid,
            nullptr,
            nullptr,
            nullptr);

        PACL oldDacl = nullptr;
        PSECURITY_DESCRIPTOR securityDescriptor = nullptr;
        DWORD daclResult = ::GetNamedSecurityInfoW(
            nativePath.data(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            nullptr,
            nullptr,
            &oldDacl,
            nullptr,
            &securityDescriptor);

        PACL newDacl = nullptr;
        if (daclResult == ERROR_SUCCESS)
        {
            EXPLICIT_ACCESS_W explicitAccess{};
            explicitAccess.grfAccessPermissions = FILE_ALL_ACCESS;
            explicitAccess.grfAccessMode = GRANT_ACCESS;
            // Allow new ACEs to inherit downward for directories so subsequent enumeration and item-by-item deletion are not blocked by child inheritance rules.
            explicitAccess.grfInheritance = isDirectory
                ? (CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE)
                : NO_INHERITANCE;
            explicitAccess.Trustee.TrusteeForm = TRUSTEE_IS_SID;
            explicitAccess.Trustee.TrusteeType = TRUSTEE_IS_GROUP;
            explicitAccess.Trustee.ptstrName = reinterpret_cast<LPWSTR>(administratorsSid);

            daclResult = ::SetEntriesInAclW(1, &explicitAccess, oldDacl, &newDacl);
            if (daclResult == ERROR_SUCCESS)
            {
                daclResult = ::SetNamedSecurityInfoW(
                    nativePath.data(),
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION,
                    nullptr,
                    nullptr,
                    newDacl,
                    nullptr);
            }
        }

        if (newDacl != nullptr)
        {
            ::LocalFree(newDacl);
        }
        if (securityDescriptor != nullptr)
        {
            ::LocalFree(securityDescriptor);
        }
        ::LocalFree(administratorsSid);

        if (detailTextOut != nullptr)
        {
            *detailTextOut = QStringLiteral("takeOwner=%1, grantDacl=%2")
                .arg(ownerResult)
                .arg(daclResult);
        }

        if (ownerResult != ERROR_SUCCESS)
        {
            return ownerResult;
        }
        return daclResult;
    }

    // removeSinglePathByWin32：
    // - Purpose: Perform a single Win32 deletion based on directory/file semantics; for reparse point directories, only delete the link itself.
    // - Returns: true if deleted; on failure, outputs the Win32 error code via lastErrorOut.
    bool removeSinglePathByWin32(
        const QString& path,
        const bool isDirectory,
        DWORD* const lastErrorOut)
    {
        const std::wstring kNativePath = QDir::toNativeSeparators(path).toStdWString();
        const BOOL kRemoveOk = isDirectory
            ? ::RemoveDirectoryW(kNativePath.c_str())
            : ::DeleteFileW(kNativePath.c_str());
        if (kRemoveOk != FALSE)
        {
            return true;
        }

        if (lastErrorOut != nullptr)
        {
            *lastErrorOut = ::GetLastError();
        }
        return false;
    }

    // schedulePathDeleteOnReboot：
    // - Purpose: Register the target in PendingFileRenameOperations for deletion by the session manager on the next boot.
    // - Note: Administrator privileges are required; a directory must be registered after its sub-items in the sequence to be deleted successfully.
    bool schedulePathDeleteOnReboot(const QString& path, DWORD* const lastErrorOut)
    {
        const std::wstring kNativePath = QDir::toNativeSeparators(path).toStdWString();
        if (::MoveFileExW(kNativePath.c_str(), nullptr, MOVEFILE_DELAY_UNTIL_REBOOT) != FALSE)
        {
            return true;
        }

        if (lastErrorOut != nullptr)
        {
            *lastErrorOut = ::GetLastError();
        }
        return false;
    }

    // deleteExpandedTargetByR3：
    // - Input: single post-order unwind target, whether privilege escalation repair is allowed;
    // - Processing: Attempt direct deletion by clearing attributes first; if it fails and privilege escalation is allowed, take ownership and grant permissions before retrying;
    // - Returns: true if deletion succeeded; on failure, writes diagnostic error text to errorTextOut.
    bool deleteExpandedTargetByR3(
        const DriverDeleteTarget& target,
        const bool allowPermissionRepair,
        bool* const permissionRepairedOut,
        QString* const errorTextOut)
    {
        if (permissionRepairedOut != nullptr)
        {
            *permissionRepairedOut = false;
        }

        (void)clearDeleteBlockingAttributes(target.path);

        DWORD lastError = ERROR_SUCCESS;
        if (removeSinglePathByWin32(target.path, target.isDirectory, &lastError))
        {
            return true;
        }

        if (!allowPermissionRepair)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("删除失败：%1（error=%2）")
                    .arg(QDir::toNativeSeparators(target.path))
                    .arg(lastError);
            }
            return false;
        }

        QString repairDetailText;
        const DWORD kRepairResult =
            takeOwnershipAndGrantFullControl(target.path, target.isDirectory, &repairDetailText);
        if (permissionRepairedOut != nullptr)
        {
            *permissionRepairedOut = true;
        }

        (void)clearDeleteBlockingAttributes(target.path);
        DWORD retryError = ERROR_SUCCESS;
        if (removeSinglePathByWin32(target.path, target.isDirectory, &retryError))
        {
            return true;
        }

        if (errorTextOut != nullptr)
        {
            *errorTextOut = QStringLiteral("强制删除失败：%1（首次 error=%2，接管所有权=%3[%4]，重试 error=%5）")
                .arg(QDir::toNativeSeparators(target.path))
                .arg(lastError)
                .arg(kRepairResult)
                .arg(repairDetailText)
                .arg(retryError);
        }
        return false;
    }

    // expandDeleteTargetsForBatch：
    // - Purpose: Expand the user-selected paths into a subsequent deletion sequence.
    // - Note: Force deletion takes ownership before enumerating each layer; otherwise, sub-items cannot be enumerated if the directory refuses enumeration.
    std::vector<DriverDeleteTarget> expandDeleteTargetsForBatch(
        const std::vector<QString>& paths,
        const bool repairPermissionWhileExpanding,
        FileDeleteBatchStats& statsInOut)
    {
        std::vector<DriverDeleteTarget> targets;
        for (const QString& path : paths)
        {
            if (repairPermissionWhileExpanding)
            {
                const QFileInfo kRootInfo(path);
                QString repairDetailText;
                (void)takeOwnershipAndGrantFullControl(path, kRootInfo.isDir(), &repairDetailText);
                (void)clearDeleteBlockingAttributes(path);
            }

            QString errorText;
            if (!appendDriverDeleteTargetsPostOrder(
                    path,
                    targets,
                    errorText,
                    repairPermissionWhileExpanding))
            {
                statsInOut.failedCount += 1U;
                statsInOut.errors.push_back(errorText);
            }
        }
        return targets;
    }

    // appendDriverDeleteFailureDetail：
    // - Purpose: Adds a hint about the source of the lock when R0 deletion fails.
    // - Note: Scanning only without terminating processes is required; bypassing the explicit confirmation flow of the file unlocker is unacceptable.
    void appendDriverDeleteFailureDetail(
        const QString& path,
        const bool isDirectory,
        const QString& baseDetailText,
        FileDeleteBatchStats& statsInOut)
    {
        QStringList errorLines;
        errorLines.push_back(baseDetailText);

        if (!isDirectory)
        {
            QStringList scanDetails;
            const std::vector<std::uint32_t> kOccupyPids =
                collectOccupyProcessIdsByPath(path, &scanDetails);
            errorLines.push_back(
                QStringLiteral("occupyPidCount=%1, autoTerminate=disabled").arg(kOccupyPids.size()));
            errorLines.push_back(
                QStringLiteral("请先使用“文件解锁器”选择并确认要结束的占用进程，再重新执行驱动删除。"));
            errorLines.append(scanDetails);
        }

        statsInOut.errors.push_back(errorLines.join(QStringLiteral(" | ")));
    }

    // deleteTreeByDriverPerNode：
    // - Purpose: Fallback path when old driver lacks kernel recursion; R3 expands post-order sequence to call single-point deletion IOCTL per item.
    // - Note: This path is restricted by R3 enumeration permissions; directory enumeration failures are expected degradation.
    void deleteTreeByDriverPerNode(
        ksword::ark::DriverHandle& driverHandle,
        const QString& rootPath,
        FileDeleteBatchStats& statsInOut)
    {
        std::vector<DriverDeleteTarget> targets;
        QString expandErrorText;
        if (!appendDriverDeleteTargetsPostOrder(rootPath, targets, expandErrorText))
        {
            statsInOut.failedCount += 1U;
            statsInOut.errors.push_back(expandErrorText);
            return;
        }

        for (const DriverDeleteTarget& target : targets)
        {
            std::string detailText;
            if (deletePathByR0Driver(driverHandle, target.path, target.isDirectory, &detailText))
            {
                if (target.isDirectory)
                {
                    statsInOut.deletedDirectoryCount += 1U;
                }
                else
                {
                    statsInOut.deletedFileCount += 1U;
                }
                continue;
            }

            statsInOut.failedCount += 1U;
            appendDriverDeleteFailureDetail(
                target.path,
                target.isDirectory,
                QString::fromStdString(detailText),
                statsInOut);
        }
    }

    // describeDriverDeleteResponse: convert R0 statistical response into a single-line readable diagnostic text.
    QString describeDriverDeleteResponse(
        const QString& path,
        const ksword::ark::DeletePathResult& driverResult)
    {
        const KSWORD_ARK_DELETE_PATH_RESPONSE& response = driverResult.response;
        QString failedPathText;
        if (response.failedPathLengthChars > 0U)
        {
            failedPathText = QString::fromWCharArray(
                response.failedPath,
                static_cast<int>(response.failedPathLengthChars));
        }

        return QStringLiteral(
            "驱动删除未完成：%1（state=%2, files=%3, dirs=%4, failed=%5, visited=%6, depth=%7, "
            "responseFlags=0x%8, lastStatus=0x%9, firstFailed=%10）")
            .arg(QDir::toNativeSeparators(path))
            .arg(response.deleteStatus)
            .arg(response.deletedFileCount)
            .arg(response.deletedDirectoryCount)
            .arg(response.failedCount)
            .arg(response.visitedCount)
            .arg(response.maxDepthReached)
            .arg(response.responseFlags, 0, 16)
            .arg(static_cast<unsigned long>(static_cast<std::uint32_t>(response.lastStatus)), 0, 16)
            .arg(failedPathText.isEmpty()
                ? QStringLiteral("-")
                : QDir::toNativeSeparators(failedPathText));
    }

    // runDriverDeleteBatch: R0 execution body.
    // - Directories are prioritized for recursive expansion within the kernel driver, ensuring clean deletion even when directory DACLs deny enumeration.
    // - Only the underlying scheme can fall back to R3 expansion when the old driver rejects recursive
    //   flags; IRP/POSIX must fail safely to avoid silently replacing the user-selected backend.
    FileDeleteBatchStats runDriverDeleteBatch(
        const std::vector<QString>& paths,
        const ksword::ark::FileDeleteBackend backend,
        const std::function<void(float)>& progressCallback)
    {
        FileDeleteBatchStats stats;

        std::string openDriverDetailText;
        ksword::ark::DriverHandle driverHandle = openKswordArkDriverHandle(&openDriverDetailText);
        if (!driverHandle.isValid())
        {
            stats.driverUnavailable = true;
            stats.failedCount += static_cast<std::uint64_t>(paths.size());
            stats.errors.push_back(
                QStringLiteral("无法连接 KswordARK 驱动设备：%1")
                    .arg(QString::fromStdString(openDriverDetailText)));
            return stats;
        }

        const ksword::ark::DriverClient kDriverClient;
        const std::size_t kTotalCount = paths.size();
        for (std::size_t index = 0; index < kTotalCount; ++index)
        {
            const QString& path = paths[index];
            const QFileInfo kPathInfo(path);
            const bool kIsDirectory = kPathInfo.isDir();
            const bool kIsReparsePointPath = isPathReparsePoint(path);
            const bool kWantRecursive = kIsDirectory && !kIsReparsePointPath;

            const QString kDriverNtPath = buildDriverNtPath(path);
            if (kDriverNtPath.isEmpty())
            {
                stats.failedCount += 1U;
                stats.errors.push_back(
                    QStringLiteral("NT 路径转换失败：%1").arg(QDir::toNativeSeparators(path)));
            }
            else
            {
                const ksword::ark::DeletePathResult kDriverResult = kDriverClient.deletePathEx(
                    driverHandle,
                    kDriverNtPath.toStdWString(),
                    kIsDirectory,
                    kWantRecursive,
                    true,
                    backend);

                if (kDriverResult.unsupported)
                {
                    if (backend == ksword::ark::FileDeleteBackend::kNative)
                    {
                        stats.driverRecursionUnsupported = true;
                        deleteTreeByDriverPerNode(driverHandle, path, stats);
                    }
                    else
                    {
                        stats.failedCount += 1U;
                        const QString kBackendText =
                            backend == ksword::ark::FileDeleteBackend::kIrp
                                ? QStringLiteral("IRP")
                                : QStringLiteral("POSIX");
                        stats.errors.push_back(QStringLiteral(
                            "当前 KswordARK 驱动不支持 R0 %1 删除后端，请重新部署本次构建的驱动：%2")
                            .arg(kBackendText)
                            .arg(QDir::toNativeSeparators(path)));
                    }
                }
                else if (!kDriverResult.io.ok)
                {
                    stats.failedCount += 1U;
                    appendDriverDeleteFailureDetail(
                        path,
                        kIsDirectory,
                        QStringLiteral("驱动删除失败：%1（%2）")
                            .arg(QDir::toNativeSeparators(path))
                            .arg(QString::fromStdString(kDriverResult.io.message)),
                        stats);
                }
                else
                {
                    const KSWORD_ARK_DELETE_PATH_RESPONSE& response = kDriverResult.response;
                    stats.deletedFileCount += response.deletedFileCount;
                    stats.deletedDirectoryCount += response.deletedDirectoryCount;
                    stats.failedCount += response.failedCount;
                    stats.skippedReparseCount += response.skippedReparseCount;
                    if (response.deleteStatus != KSWORD_ARK_DELETE_PATH_STATUS_COMPLETED)
                    {
                        if (response.failedCount == 0U)
                        {
                            // Although quota truncation cases have no failed nodes, the result is incomplete and must count as one failure.
                            stats.failedCount += 1U;
                        }
                        appendDriverDeleteFailureDetail(
                            path,
                            kIsDirectory,
                            describeDriverDeleteResponse(path, kDriverResult),
                            stats);
                    }
                }
            }

            if (progressCallback)
            {
                progressCallback(
                    5.0f + (static_cast<float>(index + 1) / static_cast<float>(kTotalCount)) * 90.0f);
            }
        }

        driverHandle.reset();
        return stats;
    }

    // runFileDeleteBatch：
    // - Input: selected path set, permission tier, and progress callback;
    // - Processing: Select deletion method based on the tier; directories are always processed in post-order sequence regardless of the tier.
    // - Returns: Statistics and failure details, aggregated and displayed by the UI thread.
    FileDeleteBatchStats runFileDeleteBatch(
        const std::vector<QString>& paths,
        const FileDeleteMode mode,
        const std::function<void(float)>& progressCallback)
    {
        FileDeleteBatchStats stats;
        if (paths.empty())
        {
            return stats;
        }

        if (mode == FileDeleteMode::kDriverR0Native)
        {
            return runDriverDeleteBatch(
                paths,
                ksword::ark::FileDeleteBackend::kNative,
                progressCallback);
        }
        if (mode == FileDeleteMode::kDriverR0Irp)
        {
            return runDriverDeleteBatch(
                paths,
                ksword::ark::FileDeleteBackend::kIrp,
                progressCallback);
        }
        if (mode == FileDeleteMode::kDriverR0Posix)
        {
            return runDriverDeleteBatch(
                paths,
                ksword::ark::FileDeleteBackend::kPosix,
                progressCallback);
        }

        if (mode == FileDeleteMode::kRecycleBin)
        {
            // QFile::moveToTrash internally requires the Shell's IFileOperation, so the COM apartment must be initialized in
            // this thread. RPC_E_CHANGED_MODE indicates an existing apartment; in this case, CoUninitialize cannot be paired.
            const HRESULT kComInitResult = ::CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
            const bool kComUninitializeNeeded = SUCCEEDED(kComInitResult);

            const std::size_t kTotalCount = paths.size();
            for (std::size_t index = 0; index < kTotalCount; ++index)
            {
                const QString& path = paths[index];
                bool removeOk = QFile::moveToTrash(path);
                if (removeOk)
                {
                    stats.recycledCount += 1U;
                }
                else
                {
                    // When the Recycle Bin is unavailable (e.g., network locations, removable drives, or disabled), fall back to permanent
                    // deletion. This alters reversibility, so it must be logged separately and the user must be informed accurately during cleanup.
                    const QFileInfo kPathInfo(path);
                    if (kPathInfo.isDir())
                    {
                        if (isPathReparsePoint(path))
                        {
                            removeOk = (::RemoveDirectoryW(
                                QDir::toNativeSeparators(path).toStdWString().c_str()) != FALSE);
                            if (removeOk)
                            {
                                stats.skippedReparseCount += 1U;
                            }
                        }
                        else
                        {
                            removeOk = QDir(path).removeRecursively();
                        }
                        if (removeOk)
                        {
                            stats.deletedDirectoryCount += 1U;
                        }
                    }
                    else
                    {
                        removeOk = QFile::remove(path);
                        if (removeOk)
                        {
                            stats.deletedFileCount += 1U;
                        }
                    }

                    if (removeOk)
                    {
                        stats.permanentlyDeleted.push_back(path);
                    }
                    else
                    {
                        stats.failedCount += 1U;
                        stats.errors.push_back(
                            QStringLiteral("删除失败：%1").arg(QDir::toNativeSeparators(path)));
                    }
                }

                if (progressCallback)
                {
                    progressCallback(
                        5.0f + (static_cast<float>(index + 1) / static_cast<float>(kTotalCount)) * 90.0f);
                }
            }

            if (kComUninitializeNeeded)
            {
                ::CoUninitialize();
            }
            return stats;
        }

        const bool kForceMode = (mode == FileDeleteMode::kForceR3);
        const bool kPendingRebootMode = (mode == FileDeleteMode::kPendingReboot);
        if (kPendingRebootMode)
        {
            // The session manager executes deletions in registration order during early startup. Writing to this table requires SeRestorePrivilege.
            (void)enableFileContextPrivilege(SE_RESTORE_NAME);
            (void)enableFileContextPrivilege(SE_BACKUP_NAME);
        }

        const std::vector<DriverDeleteTarget> kTargets =
            expandDeleteTargetsForBatch(paths, kForceMode, stats);
        const std::size_t kTotalTargetCount = kTargets.size();
        for (std::size_t index = 0; index < kTotalTargetCount; ++index)
        {
            const DriverDeleteTarget& target = kTargets[index];
            const bool kTargetIsReparsePoint = target.isDirectory && isPathReparsePoint(target.path);

            if (kPendingRebootMode)
            {
                DWORD scheduleError = ERROR_SUCCESS;
                if (schedulePathDeleteOnReboot(target.path, &scheduleError))
                {
                    stats.pendingRebootCount += 1U;
                }
                else
                {
                    stats.failedCount += 1U;
                    stats.errors.push_back(
                        QStringLiteral("登记重启后删除失败：%1（error=%2）")
                            .arg(QDir::toNativeSeparators(target.path))
                            .arg(scheduleError));
                }
            }
            else
            {
                bool permissionRepaired = false;
                QString errorText;
                if (deleteExpandedTargetByR3(target, kForceMode, &permissionRepaired, &errorText))
                {
                    if (target.isDirectory)
                    {
                        stats.deletedDirectoryCount += 1U;
                    }
                    else
                    {
                        stats.deletedFileCount += 1U;
                    }
                    if (kTargetIsReparsePoint)
                    {
                        stats.skippedReparseCount += 1U;
                    }
                }
                else
                {
                    stats.failedCount += 1U;
                    stats.errors.push_back(errorText);
                }

                if (permissionRepaired)
                {
                    stats.permissionRepairCount += 1U;
                }
            }

            if (progressCallback)
            {
                progressCallback(
                    5.0f + (static_cast<float>(index + 1) / static_cast<float>(kTotalTargetCount)) * 90.0f);
            }
        }

        return stats;
    }
}

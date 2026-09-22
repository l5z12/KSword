#include "FileDock.Support.h"

using namespace ksword::ui::file_dock;

void FileDock::createNewFileOrFolder(FilePanelWidgets& panel, bool createFolder)
{
    {
        KLogEvent event;
        info << event
            << "[FileDock] 新建请求, panel="
            << panel.panelNameText.toStdString()
            << ", type="
            << (createFolder ? "folder" : "file")
            << ", currentPath="
            << QDir::toNativeSeparators(panel.currentPath).toStdString()
            << eol;
    }

    bool ok = false;
    const QString kInputName = QInputDialog::getText(
        this,
        createFolder ? QStringLiteral("新建文件夹") : QStringLiteral("新建文件"),
        QStringLiteral("请输入名称："),
        QLineEdit::Normal,
        createFolder ? QStringLiteral("新建文件夹") : QStringLiteral("新建文件.txt"),
        &ok);
    if (!ok)
    {
        return;
    }

    const QString kTrimmedName = kInputName.trimmed();
    if (kTrimmedName.isEmpty())
    {
        return;
    }

    const QString kTargetPath = QDir(panel.currentPath).filePath(kTrimmedName);
    bool createOk = false;
    if (createFolder)
    {
        QDir dir;
        createOk = dir.mkpath(kTargetPath);
    }
    else
    {
        QFile file(kTargetPath);
        createOk = file.open(QIODevice::WriteOnly | QIODevice::Truncate);
        file.close();
    }

    if (!createOk)
    {
        KLogEvent event;
        err << event
            << "[FileDock] 新建失败, panel="
            << panel.panelNameText.toStdString()
            << ", targetPath="
            << QDir::toNativeSeparators(kTargetPath).toStdString()
            << eol;
        return;
    }

    refreshPanel(panel);

    KLogEvent event;
    info << event
        << "[FileDock] 新建成功, panel="
        << panel.panelNameText.toStdString()
        << ", targetPath="
        << QDir::toNativeSeparators(kTargetPath).toStdString()
        << eol;
}

void FileDock::renameSelectedItem(FilePanelWidgets& panel)
{
    const QString kPath = currentIndexPath(panel);
    if (kPath.isEmpty())
    {
        return;
    }

    {
        KLogEvent event;
        info << event
            << "[FileDock] 重命名请求, panel="
            << panel.panelNameText.toStdString()
            << ", oldPath="
            << QDir::toNativeSeparators(kPath).toStdString()
            << eol;
    }

    QFileInfo oldInfo(kPath);
    bool ok = false;
    const QString kNewName = QInputDialog::getText(
        this,
        QStringLiteral("重命名"),
        QStringLiteral("新名称："),
        QLineEdit::Normal,
        oldInfo.fileName(),
        &ok);
    if (!ok)
    {
        return;
    }

    const QString kTrimmedName = kNewName.trimmed();
    if (kTrimmedName.isEmpty() || kTrimmedName == oldInfo.fileName())
    {
        return;
    }

    const QString kNewPath = oldInfo.dir().filePath(kTrimmedName);
    bool renameOk = false;
    if (oldInfo.isDir())
    {
        QDir parentDir = oldInfo.dir();
        renameOk = parentDir.rename(oldInfo.fileName(), kTrimmedName);
    }
    else
    {
        renameOk = QFile::rename(kPath, kNewPath);
    }

    if (!renameOk)
    {
        KLogEvent event;
        err << event
            << "[FileDock] 重命名失败, panel="
            << panel.panelNameText.toStdString()
            << ", oldPath="
            << QDir::toNativeSeparators(kPath).toStdString()
            << ", newPath="
            << QDir::toNativeSeparators(kNewPath).toStdString()
            << eol;
        return;
    }

    refreshPanel(panel);

    KLogEvent event;
    info << event
        << "[FileDock] 重命名成功, panel="
        << panel.panelNameText.toStdString()
        << ", oldPath="
        << QDir::toNativeSeparators(kPath).toStdString()
        << ", newPath="
        << QDir::toNativeSeparators(kNewPath).toStdString()
        << eol;
}

void FileDock::deleteSelectedItem(FilePanelWidgets& panel)
{
    // Both the Delete shortcut key and the top-level right-click 'Delete' action route to recoverable Recycle
    // Bin files; stronger permission mechanisms are unified in the 'Delete Mode' submenu for explicit selection.
    deleteSelectedItemsWithMode(panel, FileDeleteMode::kRecycleBin);
}

void FileDock::deleteSelectedItemByDriver(FilePanelWidgets& panel)
{
    deleteSelectedItemsWithMode(panel, FileDeleteMode::kDriverR0Native);
}

void FileDock::deleteSelectedItemsWithMode(FilePanelWidgets& panel, const FileDeleteMode mode)
{
    // Reentrancy prevention: Deletion, like cross-panel transfer, is a batch file system write operation that requires refreshing the panel upon
    // completion. During this period, a second deletion request must not be accepted (otherwise, the two batches would overwrite each other's results).
    if (property(kFileDeleteInProgressProperty).toBool())
    {
        return;
    }

    const std::vector<QString> kPaths = selectedPaths(panel);
    if (kPaths.empty())
    {
        return;
    }

    // Mode labels must clearly explain 'reversibility + permission mechanisms':
    // The user's expectation for 'Delete' comes from the file explorer (sending to Recycle Bin, restorable), whereas the following
    // four levels are irreversible. Failing to explain this in advance makes an irreversible operation appear reversible.
    QString modeNameText;
    QString confirmTitleText;
    QString confirmBodyText;
    switch (mode)
    {
    case FileDeleteMode::kRecycleBin:
        modeNameText = QStringLiteral("删除到回收站");
        confirmTitleText = QStringLiteral("删除确认");
        confirmBodyText = QStringLiteral(
            "确定要把选中的 %1 项移到回收站吗？\n\n"
            "若某些项无法移入回收站（例如位于网络位置、可移动磁盘，或回收站已停用），"
            "将改为永久删除且无法还原；完成后会告知具体数量。")
            .arg(kPaths.size());
        break;
    case FileDeleteMode::kPermanentR3:
        modeNameText = QStringLiteral("永久删除");
        confirmTitleText = QStringLiteral("永久删除确认");
        confirmBodyText = QStringLiteral(
            "将以当前用户权限永久删除选中的 %1 项，不进入回收站、无法还原。\n\n"
            "目录会按“子项先删、目录后删”的顺序递归删除；符号链接/联接点只删除链接本身，"
            "不会跟进到链接目标。是否继续？")
            .arg(kPaths.size());
        break;
    case FileDeleteMode::kForceR3:
        modeNameText = QStringLiteral("强制删除（接管所有权）");
        confirmTitleText = QStringLiteral("强制删除确认");
        confirmBodyText = QStringLiteral(
            "将对选中的 %1 项执行强制删除：清除只读/隐藏/系统属性，必要时把所有者改为 "
            "BUILTIN\\Administrators 并授予完全控制，然后递归永久删除。\n\n"
            "所有权与访问控制项会被真实修改且不会自动还原，删除本身也无法撤销。是否继续？")
            .arg(kPaths.size());
        break;
    case FileDeleteMode::kPendingReboot:
        modeNameText = QStringLiteral("重启后删除");
        confirmTitleText = QStringLiteral("重启后删除确认");
        confirmBodyText = QStringLiteral(
            "将把选中的 %1 项登记到 PendingFileRenameOperations，由系统在下次重启的早期阶段删除。\n\n"
            "适用于正被占用、当前无法删除的目标；登记后文件在重启前仍然存在，"
            "删除结果要等重启后才能确认。是否继续？")
            .arg(kPaths.size());
        break;
    case FileDeleteMode::kDriverR0Native:
        modeNameText = QStringLiteral("R0 驱动（底层方案）");
        confirmTitleText = QStringLiteral("R0 底层删除确认");
        confirmBodyText = QStringLiteral(
            "将通过 KswordARK 驱动的底层 Zw* 方案硬删除选中的 %1 项，不进入回收站、无法还原。\n\n目录树由 R0 递归展开后序删除，因此目录拒绝列举时也能删干净；失败时会执行现有 DispositionEx 兼容重试。符号链接/联接点只删除链接本身。是否继续？")
            .arg(kPaths.size());
        break;
    case FileDeleteMode::kDriverR0Irp:
        modeNameText = QStringLiteral("R0 驱动(IRP)");
        confirmTitleText = QStringLiteral("R0 IRP 删除确认");
        confirmBodyText = QStringLiteral(
            "将由 KswordARK 驱动构造 IRP_MJ_SET_INFORMATION / FileDispositionInformation，通过完整文件系统栈硬删除选中的 %1 项，不进入回收站、无法还原。\n\n目录树仍由 R0 后序递归展开；此模式不会回退到底层方案。符号链接/联接点只删除链接本身。是否继续？")
            .arg(kPaths.size());
        break;
    case FileDeleteMode::kDriverR0Posix:
        modeNameText = QStringLiteral("R0 驱动(POSIX)");
        confirmTitleText = QStringLiteral("R0 POSIX 删除确认");
        confirmBodyText = QStringLiteral(
            "将由 KswordARK 驱动使用 FileDispositionInformationEx 的 POSIX unlink 语义，硬删除选中的 %1 项，不进入回收站、无法还原。\n\n目录树仍由 R0 后序递归展开；支持情况取决于 Windows 版本与文件系统，失败时不会回退到 IRP 或底层方案。是否继续？")
            .arg(kPaths.size());
        break;
    default:
        return;
    }

    {
        KLogEvent requestEvent;
        info << requestEvent
            << "[FileDock] 删除请求, panel="
            << panel.panelNameText.toStdString()
            << ", mode="
            << modeNameText.toStdString()
            << ", count="
            << kPaths.size()
            << eol;
    }

    // Taking ownership and PendingFileRenameOperations both require an administrator token; if
    // not elevated, force a reboot to elevate, avoiding user confusion amidst error=5 messages.
    if (mode == FileDeleteMode::kForceR3 || mode == FileDeleteMode::kPendingReboot)
    {
        if (!ks::ui::isCurrentProcessElevated())
        {
            (void)ks::ui::requestAdministratorRestartForFeature(this, modeNameText);
            return;
        }
    }

    const QMessageBox::StandardButton kUserChoice = QMessageBox::question(
        this,
        confirmTitleText,
        confirmBodyText,
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);
    if (kUserChoice != QMessageBox::Yes)
    {
        return;
    }

    const int kProgressPid = kPro.add(this, "文件", modeNameText.toStdString());
    kPro.set(kProgressPid, "删除开始", 0, 5.0f);
    setProperty(kFileDeleteInProgressProperty, true);

    // Move the entire deletion to a background thread: moveToTrash uses Shell IFileOperation (fixed tens of milliseconds per item), and recursive
    // expansion traverses the full tree. Synchronous execution during multi-select or large directory deletion would block the event loop for seconds to
    // minutes, preventing even the kPro progress bar from updating. This implementation matches transferSelectedItemsToOppositePanel in the same file.
    const bool kSourceWasLeftPanel = &panel == &leftPanel_;
    const QString kPanelNameText = panel.panelNameText;
    const QPointer<FileDock> kGuardedSelf(this);
    const QPointer<QApplication> kApplicationGuard(qApp);

    QThreadPool::globalInstance()->start(
        [kGuardedSelf, kApplicationGuard, kPaths, kPanelNameText, modeNameText, mode, kSourceWasLeftPanel, kProgressPid]()
        {
            // Progress is throttled by integer percentage: large directories generate tens of thousands of callbacks; posting every time would overwhelm the main thread's event queue.
            int lastProgressBucket = 5;
            const auto kProgressReporter =
                [&lastProgressBucket, kApplicationGuard, kProgressPid](const float progress)
                {
                    const int kBucket = static_cast<int>(progress);
                    if (kBucket <= lastProgressBucket)
                    {
                        return;
                    }
                    lastProgressBucket = kBucket;
                    if (kApplicationGuard.isNull())
                    {
                        return;
                    }
                    QMetaObject::invokeMethod(
                        kApplicationGuard.data(),
                        [kProgressPid, progress]()
                        {
                            kPro.set(kProgressPid, "删除处理中", 0, progress);
                        },
                        Qt::QueuedConnection);
                };

            FileDeleteBatchStats stats = runFileDeleteBatch(kPaths, mode, kProgressReporter);

            if (kApplicationGuard.isNull())
            {
                return;
            }

            QMetaObject::invokeMethod(
                kApplicationGuard.data(),
                [kGuardedSelf,
                    stats = std::move(stats),
                    kPanelNameText,
                    modeNameText,
                    mode,
                    kSourceWasLeftPanel,
                    kProgressPid,
                    originalCount = kPaths.size()]()
                {
                    kPro.set(kProgressPid, "删除完成", 0, 100.0f);
                    if (kGuardedSelf.isNull())
                    {
                        return;
                    }

                    FileDock* const kDock = kGuardedSelf.data();
                    kDock->setProperty(kFileDeleteInProgressProperty, false);
                    FilePanelWidgets& completedPanel = kSourceWasLeftPanel
                        ? kDock->leftPanel_
                        : kDock->rightPanel_;
                    kDock->refreshPanel(completedPanel);

                    QStringList summaryLines;
                    if (stats.recycledCount > 0U)
                    {
                        summaryLines << QStringLiteral("已移入回收站：%1 项").arg(stats.recycledCount);
                    }
                    if ((stats.deletedFileCount + stats.deletedDirectoryCount) > 0U)
                    {
                        summaryLines << QStringLiteral("已永久删除：文件 %1 个、目录 %2 个")
                            .arg(stats.deletedFileCount)
                            .arg(stats.deletedDirectoryCount);
                    }
                    if (stats.pendingRebootCount > 0U)
                    {
                        summaryLines << QStringLiteral("已登记重启后删除：%1 项").arg(stats.pendingRebootCount);
                    }
                    if (stats.skippedReparseCount > 0U)
                    {
                        summaryLines << QStringLiteral("重解析点只删除了链接本身：%1 项")
                            .arg(stats.skippedReparseCount);
                    }
                    if (stats.permissionRepairCount > 0U)
                    {
                        summaryLines << QStringLiteral("触发接管所有权/授权的项：%1 项（所有权与 DACL 已被修改，不会自动还原）")
                            .arg(stats.permissionRepairCount);
                    }
                    if (stats.driverRecursionUnsupported)
                    {
                        summaryLines << QStringLiteral("当前 R0 驱动不支持内核递归删除，已回退为 R3 展开逐项删除。");
                    }
                    if (stats.failedCount > 0U)
                    {
                        summaryLines << QStringLiteral("失败：%1 项").arg(stats.failedCount);
                    }

                    {
                        KLogEvent completionEvent;
                        (stats.failedCount > 0U ? warn : info) << completionEvent
                            << "[FileDock] 删除完成, panel="
                            << kPanelNameText.toStdString()
                            << ", mode="
                            << modeNameText.toStdString()
                            << ", requested="
                            << originalCount
                            << ", recycled="
                            << stats.recycledCount
                            << ", files="
                            << stats.deletedFileCount
                            << ", dirs="
                            << stats.deletedDirectoryCount
                            << ", pendingReboot="
                            << stats.pendingRebootCount
                            << ", failed="
                            << stats.failedCount
                            << ", errorPreview=\n"
                            << buildLogPreviewText(stats.errors).toStdString()
                            << eol;
                    }

                    if (stats.driverUnavailable)
                    {
                        QMessageBox::warning(
                            kDock,
                            QStringLiteral("驱动删除"),
                            QStringLiteral("无法连接 KswordARK 驱动设备，请先启用 R0 驱动。\n\n%1")
                                .arg(buildLogPreviewText(stats.errors)));
                        return;
                    }

                    // Explicitly notify when some items cannot be moved to the Recycle Bin: these items are
                    // unrecoverable, allowing the user to determine if recovery via the Recycle Bin is still possible.
                    if (!stats.permanentlyDeleted.isEmpty())
                    {
                        QMessageBox::warning(
                            kDock,
                            QStringLiteral("部分项目已永久删除"),
                            QStringLiteral("有 %1 项无法移入回收站，已被永久删除，无法从回收站还原：\n\n%2")
                                .arg(stats.permanentlyDeleted.size())
                                .arg(buildLogPreviewText(stats.permanentlyDeleted)));
                    }

                    if (stats.failedCount > 0U)
                    {
                        QMessageBox::warning(
                            kDock,
                            modeNameText,
                            QStringLiteral("%1 未全部完成。\n\n%2\n\n失败明细（最多显示前若干条）：\n%3")
                                .arg(modeNameText)
                                .arg(summaryLines.join(QStringLiteral("\n")))
                                .arg(buildLogPreviewText(stats.errors)));
                        return;
                    }

                    if (mode == FileDeleteMode::kPendingReboot && stats.pendingRebootCount > 0U)
                    {
                        QMessageBox::information(
                            kDock,
                            modeNameText,
                            QStringLiteral("%1\n\n目标仍然存在，系统会在下次重启的早期阶段执行删除。")
                                .arg(summaryLines.join(QStringLiteral("\n"))));
                    }
                },
                Qt::QueuedConnection);
        });
}

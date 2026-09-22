#include "FileDetailDialog.h"

using namespace ksword::ui::file_dock;

void FileDock::showPanelContextMenu(FilePanelWidgets& panel, const QPoint& localPos)
{
    KLogEvent menuOpenEvent;
    dbg << menuOpenEvent
        << "[FileDock] 打开右键菜单, panel="
        << panel.panelNameText.toStdString()
        << ", localPos=("
        << localPos.x()
        << ","
        << localPos.y()
        << ")"
        << eol;

    // On right-clicking a row, prioritize ensuring the 'hit row' matches the 'selected set'.
    // Note: If the hit row is already selected, preserve the original multi-selection; if the hit row is unselected, switch to single-row selection.
    QAbstractItemView* menuView =
        (panel.viewModeCombo->currentIndex() <= 1)
        ? static_cast<QAbstractItemView*>(panel.compactFileView)
        : static_cast<QAbstractItemView*>(panel.fileView);
    const QModelIndex kHitIndex = menuView->indexAt(localPos);
    QItemSelectionModel* selectionModel = menuView->selectionModel();
    if (kHitIndex.isValid() && selectionModel != nullptr)
    {
        const QModelIndex kHitRowIndex = kHitIndex.siblingAtColumn(0);
        const bool kHitAlreadySelected =
            selectionModel->isRowSelected(kHitIndex.row(), kHitIndex.parent()) ||
            (kHitRowIndex.isValid() && selectionModel->isSelected(kHitRowIndex));
        if (!kHitAlreadySelected)
        {
            selectionModel->select(kHitIndex, QItemSelectionModel::ClearAndSelect | QItemSelectionModel::Rows);
        }
        // Right-click menu entry only syncs the current focus; do not update the current index to avoid corrupting the multi-selection set.
        selectionModel->setCurrentIndex(kHitIndex, QItemSelectionModel::NoUpdate);
    }

    // Data used by the right-click menu is unified from the 'currently selected set'.
    const std::vector<QString> kMenuPaths = selectedPaths(panel);
    const bool kHasSelection = !kMenuPaths.empty();
    const bool kIsSingleSelection = kMenuPaths.size() == 1;
    const QString kFirstPath = kIsSingleSelection ? kMenuPaths.front() : QString();
    DWORD firstFileIntegrityRid = 0;
    bool firstFileIntegrityImplicitMedium = false;
    QString firstFileIntegrityDetailText;
    const bool kFirstFileIntegrityKnown = kHasSelection &&
        queryFileIntegrityRid(
            kMenuPaths.front(),
            &firstFileIntegrityRid,
            &firstFileIntegrityImplicitMedium,
            &firstFileIntegrityDetailText);

    // Count selected content types to control menu availability, preventing accidental triggering of single-file functions during multi-selection.
    bool hasAnyFile = false;
    QStringList linkTargetList;
    for (const QString& path : kMenuPaths)
    {
        QFileInfo info(path);
        hasAnyFile = hasAnyFile || info.isFile();
        if (isPathReparsePoint(path))
        {
            const ks::file::ReparsePointQueryResult kReparseResult = queryReparsePointForUi(path);
            const QString kTargetText = reparseTargetFromResult(kReparseResult).trimmed();
            if (!kTargetText.isEmpty() && !linkTargetList.contains(kTargetText, Qt::CaseInsensitive))
            {
                linkTargetList.push_back(kTargetText);
            }
        }
    }
    const QString kFirstLinkTarget = (!linkTargetList.isEmpty() && kIsSingleSelection) ? linkTargetList.front() : QString();

    // Copy/Move follows the dual-pane file manager semantics: selected items in the source panel are dropped directly onto the target panel.
    // Menu text must clearly specify the target panel to avoid user confusion with Windows clipboard 'Copy/Cut' operations.
    FilePanelWidgets* const kTransferTargetPanel = oppositePanelFor(panel);
    const QString kTransferTargetText = (kTransferTargetPanel != nullptr)
        ? kTransferTargetPanel->panelNameText
        : QStringLiteral("对侧面板");
    const QString kLocalizedTransferTargetText = ks::i18n::displayText(kTransferTargetText);
    const QString kCopyToPanelText = ks::i18n::displayText(QStringLiteral("复制到%1"))
        .arg(kLocalizedTransferTargetText);
    const QString kMoveToPanelText = ks::i18n::displayText(QStringLiteral("移动到%1"))
        .arg(kLocalizedTransferTargetText);

    QMenu menu(this);
    menu.setStyleSheet(buildContextMenuStyle());
    QAction* openAction = menu.addAction(QIcon(":/Icon/process_start.svg"), QStringLiteral("打开/运行"));
    QAction* copyPathAction = menu.addAction(QIcon(":/Icon/process_copy_cell.svg"), QStringLiteral("复制路径(Ctrl+C)"));
    QAction* copyKernelPathAction = menu.addAction(QIcon(":/Icon/process_copy_cell.svg"), QStringLiteral("复制内核模式地址"));
    QAction* copyShortNameAction = menu.addAction(QIcon(":/Icon/process_copy_cell.svg"), QStringLiteral("复制短文件名"));
    QAction* copyLinkTargetAction = menu.addAction(QIcon(":/Icon/process_copy_cell.svg"), QStringLiteral("复制链接目标"));
    QAction* openLinkTargetAction = menu.addAction(QIcon(":/Icon/process_start.svg"), QStringLiteral("打开链接目标"));
    QAction* locateLinkTargetAction = menu.addAction(QIcon(":/Icon/process_open_folder.svg"), QStringLiteral("定位链接目标"));
    menu.addSeparator();
    QAction* copyAction = menu.addAction(QIcon(":/Icon/log_copy.svg"), kCopyToPanelText);
    QAction* cutAction = menu.addAction(QIcon(":/Icon/process_suspend.svg"), kMoveToPanelText);
    QAction* renameAction = menu.addAction(QIcon(":/Icon/process_priority.svg"), QStringLiteral("重命名(F2)"));
    QAction* deleteAction = menu.addAction(QIcon(":/Icon/process_terminate.svg"), QStringLiteral("删除(Delete)"));
    // Delete modes are ordered by increasing permission strength: the lower the item, the more irreversible it is and the higher the required permissions.
    QMenu* deleteModeMenu = menu.addMenu(QIcon(":/Icon/process_terminate.svg"), QStringLiteral("删除方式（递归/多权限）"));
    deleteModeMenu->setToolTipsVisible(true);
    QAction* permanentDeleteAction = deleteModeMenu->addAction(
        QIcon(":/Icon/process_terminate.svg"), QStringLiteral("永久删除（R3·当前权限）"));
    permanentDeleteAction->setToolTip(
        QStringLiteral("以当前用户权限递归永久删除，不进回收站；目录按子项先删、目录后删的顺序处理。"));
    QAction* forceDeleteAction = deleteModeMenu->addAction(
        QIcon(":/Icon/file_owner.svg"), QStringLiteral("强制删除（R3·接管所有权）"));
    forceDeleteAction->setToolTip(
        QStringLiteral("清除只读/隐藏/系统属性，必要时接管所有权并授予完全控制后再递归删除；需要管理员权限。"));
    QAction* pendingRebootDeleteAction = deleteModeMenu->addAction(
        QIcon(":/Icon/process_resume.svg"), QStringLiteral("重启后删除（R3·启动时执行）"));
    pendingRebootDeleteAction->setToolTip(
        QStringLiteral("登记 PendingFileRenameOperations，由系统在下次重启早期删除；适合正被占用的目标，需要管理员权限。"));
    // R0 serves as a top-level shortcut entry to avoid forcing users to navigate through the 'Deletion Method' submenu;
    // the three actions still share a unified irreversible confirmation, background recursion, and statistics pipeline.
    QMenu* r0DeleteMenu = menu.addMenu(
        QIcon(":/Icon/process_terminate.svg"), QStringLiteral("R0"));
    r0DeleteMenu->setToolTipsVisible(true);
    QAction* driverNativeDeleteAction = r0DeleteMenu->addAction(
        QIcon(":/Icon/process_terminate.svg"), QStringLiteral("驱动（底层方案）"));
    driverNativeDeleteAction->setToolTip(QStringLiteral(
        "由 R0 用 ZwCreateFile/ZwSetInformationFile 删除；失败时保留现有的 DispositionEx 兼容重试。"));
    QAction* driverIrpDeleteAction = r0DeleteMenu->addAction(
        QIcon(":/Icon/process_terminate.svg"), QStringLiteral("驱动(IRP)"));
    driverIrpDeleteAction->setToolTip(QStringLiteral(
        "由 R0 构造 IRP_MJ_SET_INFORMATION/FileDispositionInformation 并投递完整文件系统栈；不回退到底层方案。"));
    QAction* driverPosixDeleteAction = r0DeleteMenu->addAction(
        QIcon(":/Icon/process_terminate.svg"), QStringLiteral("驱动(POSIX)"));
    driverPosixDeleteAction->setToolTip(QStringLiteral(
        "由 R0 使用 FileDispositionInformationEx 的 POSIX unlink 语义；是否可用取决于系统与文件系统，不回退到其它后端。"));
    QAction* unlockByDriverAction = menu.addAction(
        QIcon(":/Icon/handle_close.svg"),
        ks::i18n::displayText(QStringLiteral("文件解锁器")));
    unlockByDriverAction->setToolTip(QStringLiteral("在文件属性中扫描占用，并提供关闭句柄、R3/R0 结束进程操作"));
    QMenu* addOplockMenu = menu.addMenu(QIcon(":/Icon/plus.svg"), QStringLiteral("添加 Oplock（访问计数）"));
    QAction* addOplockLevel1Action = addOplockMenu->addAction(QStringLiteral("Level 1 - 独占读写缓存，别人访问会计数"));
    QAction* addOplockLevel2Action = addOplockMenu->addAction(QStringLiteral("Level 2 - 共享只读缓存，别人写入会计数"));
    QAction* addOplockBatchAction = addOplockMenu->addAction(QStringLiteral("Batch - 缓存反复打开关闭，访问时计数"));
    QAction* addOplockFilterAction = addOplockMenu->addAction(QStringLiteral("Filter - 扫描器/过滤器用，访问前计数"));
    QAction* showOplockRecordsAction = menu.addAction(QIcon(":/Icon/process_list.svg"), QStringLiteral("查看 Oplock 访问记录"));
    QAction* releaseOplockAction = menu.addAction(QIcon(":/Icon/process_resume.svg"), QStringLiteral("释放当前 Oplock"));
    QAction* releaseAllOplocksAction = menu.addAction(QIcon(":/Icon/process_resume.svg"), QStringLiteral("释放全部 Oplock"));
    QAction* takeOwnerAction = menu.addAction(QIcon(":/Icon/file_owner.svg"), QStringLiteral("取得所有权"));
    QMenu* fileIntegritySubMenu = menu.addMenu(QIcon(":/Icon/file_owner.svg"), QStringLiteral("文件完整性"));
    fileIntegritySubMenu->setToolTipsVisible(true);
    fileIntegritySubMenu->setEnabled(kHasSelection);
    if (!kFirstFileIntegrityKnown && kHasSelection)
    {
        fileIntegritySubMenu->setToolTip(QStringLiteral("当前文件完整性读取失败：%1")
            .arg(firstFileIntegrityDetailText));
    }
    else if (kFirstFileIntegrityKnown && firstFileIntegrityImplicitMedium)
    {
        fileIntegritySubMenu->setToolTip(QStringLiteral("当前未设置显式 Mandatory Label，Windows 按 Medium 处理。"));
    }
    else if (kHasSelection && kMenuPaths.size() > 1U)
    {
        fileIntegritySubMenu->setToolTip(QStringLiteral("多选时圆点按第一项的文件完整性显示，执行时会批量写入所有选中项。"));
    }
    for (const FileIntegrityLevelPreset& preset : kFileIntegrityLevelPresets)
    {
        const bool kIsCurrentLevel = kFirstFileIntegrityKnown && firstFileIntegrityRid == preset.rid;
        QAction* integrityAction = fileIntegritySubMenu->addAction(
            QIcon(":/Icon/file_owner.svg"),
            QStringLiteral("%1 %2 - %3")
                .arg(kIsCurrentLevel ? QStringLiteral("●") : QStringLiteral(" "))
                .arg(QString::fromLatin1(preset.nameText))
                .arg(QString::fromUtf8(preset.detailText)));
        integrityAction->setData(static_cast<unsigned int>(preset.rid));
    }
    menu.addSeparator();
    QAction* newFileAction = menu.addAction(QIcon(":/Icon/process_details.svg"), QStringLiteral("新建文件"));
    QAction* newFolderAction = menu.addAction(QIcon(":/Icon/process_open_folder.svg"), QStringLiteral("新建文件夹"));
    QAction* openTerminalAction = menu.addAction(QIcon(":/Icon/process_tree.svg"), QStringLiteral("在终端中打开"));
    menu.addSeparator();
    QAction* columnAction = menu.addAction(QIcon(":/Icon/process_list.svg"), QStringLiteral("选择列..."));
    QAction* detailAction = menu.addAction(QIcon(":/Icon/process_details.svg"), QStringLiteral("属性..."));
    menu.addSeparator();

    // Move the analysis action to the top-level menu to reduce nesting and improve right-click operation efficiency.
    QAction* hashAction = menu.addAction(QIcon(":/Icon/log_track.svg"), QStringLiteral("计算哈希值"));
    QAction* signAction = menu.addAction(QIcon(":/Icon/process_critical.svg"), QStringLiteral("检查数字签名"));
    QAction* entropyAction = menu.addAction(QIcon(":/Icon/disk_analyze.svg"), QStringLiteral("计算熵值"));
    QAction* hexAction = menu.addAction(QIcon(":/Icon/process_details.svg"), QStringLiteral("十六进制查看"));
    QAction* peAction = menu.addAction(QIcon(":/Icon/process_list.svg"), QStringLiteral("在PE查看器中打开"));
    QAction* mappedProcessScanAction = menu.addAction(QIcon(":/Icon/process_tree.svg"), QStringLiteral("扫描映射进程(R0)"));
    QMenu* pluginMenu = menu.addMenu(QIcon(":/Icon/process_start.svg"), QStringLiteral("插件"));

    // Dynamically enable menu items based on the selected set to ensure consistent behavior for 'multi-select' and 'right-click actions'.
    const bool kSingleFileOnly = kIsSingleSelection && QFileInfo(kFirstPath).isFile();
    ks::plugin_host::InvocationContext pluginContext;
    pluginContext.targetKind = ks::plugin_host::TargetKind::kFile;
    pluginContext.filePath = kFirstPath;
    ks::plugin_host::populateTargetMenu(pluginMenu, this, pluginContext);
    const bool kFirstPathHasOplock = kSingleFileOnly && hasActiveOplockForPath(kFirstPath);
    const std::uint64_t kFirstPathOplockBreakCount = kFirstPathHasOplock
        ? activeOplockBreakCountForPath(kFirstPath)
        : 0U;
    const std::size_t kFirstPathOplockAccessProcessCount = kFirstPathHasOplock
        ? activeOplockAccessProcessCountForPath(kFirstPath)
        : 0U;
    const std::size_t kCurrentOplockCount = activeOplockCount();
    openAction->setEnabled(kHasSelection);
    copyPathAction->setEnabled(kHasSelection);
    copyKernelPathAction->setEnabled(kHasSelection);
    copyShortNameAction->setEnabled(kHasSelection);
    copyLinkTargetAction->setEnabled(!linkTargetList.isEmpty());
    openLinkTargetAction->setEnabled(!kFirstLinkTarget.isEmpty());
    locateLinkTargetAction->setEnabled(!kFirstLinkTarget.isEmpty());
    copyAction->setEnabled(kHasSelection);
    cutAction->setEnabled(kHasSelection);
    renameAction->setEnabled(kIsSingleSelection);
    deleteAction->setEnabled(kHasSelection);
    deleteModeMenu->setEnabled(kHasSelection);
    permanentDeleteAction->setEnabled(kHasSelection);
    forceDeleteAction->setEnabled(kHasSelection);
    pendingRebootDeleteAction->setEnabled(kHasSelection);
    r0DeleteMenu->setEnabled(kHasSelection);
    driverNativeDeleteAction->setEnabled(kHasSelection);
    driverIrpDeleteAction->setEnabled(kHasSelection);
    driverPosixDeleteAction->setEnabled(kHasSelection);
    unlockByDriverAction->setEnabled(kIsSingleSelection);
    const bool kCanAddOplock = kSingleFileOnly && !kFirstPathHasOplock;
    addOplockMenu->setEnabled(kCanAddOplock);
    addOplockLevel1Action->setEnabled(kCanAddOplock);
    addOplockLevel2Action->setEnabled(kCanAddOplock);
    addOplockBatchAction->setEnabled(kCanAddOplock);
    addOplockFilterAction->setEnabled(kCanAddOplock);
    if (kFirstPathHasOplock)
    {
        showOplockRecordsAction->setText(
            QStringLiteral("查看 Oplock 访问记录（%1 个进程）").arg(kFirstPathOplockAccessProcessCount));
        releaseOplockAction->setText(
            QStringLiteral("释放当前 Oplock（已触发 %1 次）").arg(kFirstPathOplockBreakCount));
    }
    showOplockRecordsAction->setEnabled(kFirstPathHasOplock);
    releaseOplockAction->setEnabled(kFirstPathHasOplock);
    releaseAllOplocksAction->setEnabled(kCurrentOplockCount > 0U);
    takeOwnerAction->setEnabled(kHasSelection);
    detailAction->setEnabled(kHasSelection);
    hashAction->setEnabled(hasAnyFile);
    signAction->setEnabled(hasAnyFile);
    entropyAction->setEnabled(hasAnyFile);
    hexAction->setEnabled(kSingleFileOnly);
    peAction->setEnabled(kSingleFileOnly);
    mappedProcessScanAction->setEnabled(hasAnyFile);
    pluginMenu->setEnabled(kSingleFileOnly);

    QAction* selectedAction = menu.exec(menuView->viewport()->mapToGlobal(localPos));
    if (selectedAction == nullptr)
    {
        KLogEvent menuCancelEvent;
        dbg << menuCancelEvent
            << "[FileDock] 右键菜单取消, panel="
            << panel.panelNameText.toStdString()
            << eol;
        return;
    }

    {
        KLogEvent menuActionEvent;
        info << menuActionEvent
            << "[FileDock] 右键菜单执行动作, panel="
            << panel.panelNameText.toStdString()
            << ", action="
            << selectedAction->text().toStdString()
            << ", selectedCount="
            << kMenuPaths.size()
            << eol;
    }

    if (selectedAction->parent() == fileIntegritySubMenu)
    {
        const DWORD kIntegrityRid = selectedAction->data().toUInt();
        setSelectedFileIntegrityLevel(
            panel,
            kIntegrityRid,
            fileIntegrityNameFromRid(kIntegrityRid));
        return;
    }
    if (selectedAction == openAction)
    {
        openSelectedItems(panel);
        return;
    }
    if (selectedAction == copyPathAction)
    {
        copySelectedItemPath(panel);
        return;
    }
    if (selectedAction == copyKernelPathAction)
    {
        copySelectedItemKernelPath(panel);
        return;
    }
    if (selectedAction == copyShortNameAction)
    {
        copySelectedItemShortName(panel);
        return;
    }
    if (selectedAction == copyLinkTargetAction)
    {
        QApplication::clipboard()->setText(linkTargetList.join(QStringLiteral("\n")));
        KLogEvent event;
        info << event
            << "[FileDock] 复制链接目标到剪贴板, panel="
            << panel.panelNameText.toStdString()
            << ", count="
            << linkTargetList.size()
            << eol;
        return;
    }
    if (selectedAction == openLinkTargetAction)
    {
        const bool kOpenOk = QDesktopServices::openUrl(QUrl::fromLocalFile(kFirstLinkTarget));
        if (!kOpenOk)
        {
            QMessageBox::warning(
                this,
                QStringLiteral("打开链接目标"),
                QStringLiteral("无法打开链接目标：%1").arg(QDir::toNativeSeparators(kFirstLinkTarget)));
        }
        return;
    }
    if (selectedAction == locateLinkTargetAction)
    {
        const QFileInfo kTargetInfo(kFirstLinkTarget);
        const QString kLocatePath = kTargetInfo.isDir()
            ? kTargetInfo.absoluteFilePath()
            : kTargetInfo.absolutePath();
        if (kLocatePath.trimmed().isEmpty() || !QDir(kLocatePath).exists())
        {
            QMessageBox::warning(
                this,
                QStringLiteral("定位链接目标"),
                QStringLiteral("目标所在目录不存在或不可访问：%1").arg(QDir::toNativeSeparators(kFirstLinkTarget)));
            return;
        }
        navigateToPath(panel, kLocatePath, true);
        return;
    }
    if (selectedAction == copyAction)
    {
        copySelectedItems(panel);
        return;
    }
    if (selectedAction == cutAction)
    {
        cutSelectedItems(panel);
        return;
    }
    if (selectedAction == renameAction)
    {
        renameSelectedItem(panel);
        return;
    }
    if (selectedAction == deleteAction)
    {
        deleteSelectedItem(panel);
        return;
    }
    if (selectedAction == permanentDeleteAction)
    {
        deleteSelectedItemsWithMode(panel, FileDeleteMode::kPermanentR3);
        return;
    }
    if (selectedAction == forceDeleteAction)
    {
        deleteSelectedItemsWithMode(panel, FileDeleteMode::kForceR3);
        return;
    }
    if (selectedAction == pendingRebootDeleteAction)
    {
        deleteSelectedItemsWithMode(panel, FileDeleteMode::kPendingReboot);
        return;
    }
    if (selectedAction == driverNativeDeleteAction)
    {
        deleteSelectedItemByDriver(panel);
        return;
    }
    if (selectedAction == driverIrpDeleteAction)
    {
        deleteSelectedItemsWithMode(panel, FileDeleteMode::kDriverR0Irp);
        return;
    }
    if (selectedAction == driverPosixDeleteAction)
    {
        deleteSelectedItemsWithMode(panel, FileDeleteMode::kDriverR0Posix);
        return;
    }
    if (selectedAction == unlockByDriverAction)
    {
        unlockSelectedItemsByDriver(panel);
        return;
    }
    if (selectedAction == addOplockLevel1Action)
    {
        addOplockToSelectedFile(panel, FileOplockLevel::kLevel1);
        return;
    }
    if (selectedAction == addOplockLevel2Action)
    {
        addOplockToSelectedFile(panel, FileOplockLevel::kLevel2);
        return;
    }
    if (selectedAction == addOplockBatchAction)
    {
        addOplockToSelectedFile(panel, FileOplockLevel::kBatch);
        return;
    }
    if (selectedAction == addOplockFilterAction)
    {
        addOplockToSelectedFile(panel, FileOplockLevel::kFilter);
        return;
    }
    if (selectedAction == showOplockRecordsAction)
    {
        showSelectedFileOplockAccessRecords(panel);
        return;
    }
    if (selectedAction == releaseOplockAction)
    {
        releaseSelectedFileOplock(panel);
        return;
    }
    if (selectedAction == releaseAllOplocksAction)
    {
        releaseAllActiveOplocks(true);
        return;
    }
    if (selectedAction == takeOwnerAction)
    {
        takeOwnershipSelectedItems(panel);
        return;
    }
    if (selectedAction == newFileAction)
    {
        createNewFileOrFolder(panel, false);
        return;
    }
    if (selectedAction == newFolderAction)
    {
        createNewFileOrFolder(panel, true);
        return;
    }
    if (selectedAction == openTerminalAction)
    {
        const QString kWorkPath = panel.currentPath.isEmpty() ? QDir::homePath() : panel.currentPath;
        DWORD terminalErrorCode = ERROR_SUCCESS;
        const bool kStartOk = openCommandPromptInDirectory(kWorkPath, &terminalErrorCode);
        KLogEvent terminalEvent;
        if (!kStartOk)
        {
            warn << terminalEvent
                << "[FileDock] 在终端中打开失败, panel="
                << panel.panelNameText.toStdString()
                << ", workPath="
                << QDir::toNativeSeparators(kWorkPath).toStdString()
                << ", error="
                << terminalErrorCode
                << eol;
        }
        else
        {
            info << terminalEvent
                << "[FileDock] 在终端中打开完成, panel="
                << panel.panelNameText.toStdString()
                << ", workPath="
                << QDir::toNativeSeparators(kWorkPath).toStdString()
                << eol;
        }
        return;
    }
    if (selectedAction == columnAction)
    {
        showColumnManagerDialog(panel);
        return;
    }
    if (selectedAction == detailAction)
    {
        QStringList detailPaths;
        detailPaths.reserve(static_cast<qsizetype>(kMenuPaths.size()));
        for (const QString& path : kMenuPaths) detailPaths.push_back(path);
        showFileDetailDialog(detailPaths);

        KLogEvent detailEvent;
        info << detailEvent
            << "[FileDock] 属性窗口打开完成, panel="
            << panel.panelNameText.toStdString()
            << ", selectedCount="
            << kMenuPaths.size()
            << eol;
        return;
    }
    if (selectedAction == hashAction)
    {
        // Hash calculation supports multi-selection: compute only for file entries, skip directories automatically.
        if (!hasAnyFile)
        {
            KLogEvent hashEmptyEvent;
            warn << hashEmptyEvent
                << "[FileDock] 哈希计算取消：未选中文件, panel="
                << panel.panelNameText.toStdString()
                << eol;
            return;
        }

        KLogEvent hashEvent;
        int successCount = 0;
        QStringList failedLines;
        for (const QString& path : kMenuPaths)
        {
            QFileInfo fileInfo(path);
            if (!fileInfo.isFile())
            {
                continue;
            }

            QFile file(path);
            if (!file.open(QIODevice::ReadOnly))
            {
                failedLines << QStringLiteral("%1 | 无法打开文件。")
                    .arg(QDir::toNativeSeparators(path));
                continue;
            }

            QCryptographicHash md5(QCryptographicHash::Md5);
            QCryptographicHash sha1(QCryptographicHash::Sha1);
            QCryptographicHash sha256(QCryptographicHash::Sha256);
            while (!file.atEnd())
            {
                const QByteArray kChunk = file.read(1024 * 256);
                md5.addData(kChunk);
                sha1.addData(kChunk);
                sha256.addData(kChunk);
            }
            file.close();

            successCount += 1;
            info << hashEvent
                << "[FileDock] 哈希计算结果, filePath="
                << QDir::toNativeSeparators(path).toStdString()
                << ", md5="
                << QString::fromLatin1(md5.result().toHex()).toStdString()
                << ", sha1="
                << QString::fromLatin1(sha1.result().toHex()).toStdString()
                << ", sha256="
                << QString::fromLatin1(sha256.result().toHex()).toStdString()
                << eol;
        }

        if (!failedLines.isEmpty())
        {
            warn << hashEvent
                << "[FileDock] 哈希计算部分失败, panel="
                << panel.panelNameText.toStdString()
                << ", successCount="
                << successCount
                << ", failCount="
                << failedLines.size()
                << ", failedPreview=\n"
                << buildLogPreviewText(failedLines).toStdString()
                << eol;
        }

        info << hashEvent
            << "[FileDock] 哈希计算完成, panel="
            << panel.panelNameText.toStdString()
            << ", successCount="
            << successCount
            << ", failCount="
            << failedLines.size()
            << eol;
        return;
    }
    if (selectedAction == signAction)
    {
        // Digital signature entry and property page linkage; supports multi-selection to open details individually.
        if (!hasAnyFile)
        {
            KLogEvent signEmptyEvent;
            warn << signEmptyEvent
                << "[FileDock] 签名检查取消：未选中文件, panel="
                << panel.panelNameText.toStdString()
                << eol;
            return;
        }

        constexpr std::size_t kMaxAutoOpenSignCount = 8;
        std::size_t openedCount = 0;
        for (const QString& path : kMenuPaths)
        {
            if (!QFileInfo(path).isFile())
            {
                continue;
            }
            if (openedCount >= kMaxAutoOpenSignCount)
            {
                break;
            }
            showFileDetailDialog(path);
            openedCount += 1;
        }

        const std::size_t kFileSelectionCount = static_cast<std::size_t>(std::count_if(
            kMenuPaths.begin(),
            kMenuPaths.end(),
            [](const QString& path)
            {
                return QFileInfo(path).isFile();
            }));
        KLogEvent signEvent;
        if (openedCount == kMaxAutoOpenSignCount && kFileSelectionCount > kMaxAutoOpenSignCount)
        {
            warn << signEvent
                << "[FileDock] 签名检查已截断打开数量, panel="
                << panel.panelNameText.toStdString()
                << ", openedCount="
                << openedCount
                << ", fileSelectionCount="
                << kFileSelectionCount
                << eol;
        }

        info << signEvent
            << "[FileDock] 签名检查完成, panel="
            << panel.panelNameText.toStdString()
            << ", openedCount="
            << openedCount
            << ", fileSelectionCount="
            << kFileSelectionCount
            << eol;
        return;
    }
    if (selectedAction == entropyAction)
    {
        // Entropy calculation supports multi-selection: count only file entries.
        if (!hasAnyFile)
        {
            KLogEvent entropyEmptyEvent;
            warn << entropyEmptyEvent
                << "[FileDock] 熵值计算取消：未选中文件, panel="
                << panel.panelNameText.toStdString()
                << eol;
            return;
        }

        KLogEvent entropyEvent;
        int successCount = 0;
        QStringList failedLines;
        for (const QString& path : kMenuPaths)
        {
            QFileInfo fileInfo(path);
            if (!fileInfo.isFile())
            {
                continue;
            }

            QFile file(path);
            if (!file.open(QIODevice::ReadOnly))
            {
                failedLines << QStringLiteral("%1 | 无法打开文件。")
                    .arg(QDir::toNativeSeparators(path));
                continue;
            }

            std::array<std::uint64_t, 256> bucket{};
            std::uint64_t totalCount = 0;
            while (!file.atEnd())
            {
                const QByteArray kChunk = file.read(1024 * 256);
                for (unsigned char byteValue : kChunk)
                {
                    bucket[byteValue] += 1;
                    totalCount += 1;
                }
            }
            file.close();

            double entropy = 0.0;
            if (totalCount > 0)
            {
                for (std::uint64_t count : bucket)
                {
                    if (count == 0)
                    {
                        continue;
                    }
                    const double kP = static_cast<double>(count) / static_cast<double>(totalCount);
                    entropy -= kP * std::log2(kP);
                }
            }

            successCount += 1;
            info << entropyEvent
                << "[FileDock] 熵值计算结果, filePath="
                << QDir::toNativeSeparators(path).toStdString()
                << ", entropy="
                << QString::number(entropy, 'f', 4).toStdString()
                << eol;
        }

        if (!failedLines.isEmpty())
        {
            warn << entropyEvent
                << "[FileDock] 熵值计算部分失败, panel="
                << panel.panelNameText.toStdString()
                << ", successCount="
                << successCount
                << ", failCount="
                << failedLines.size()
                << ", failedPreview=\n"
                << buildLogPreviewText(failedLines).toStdString()
                << eol;
        }

        info << entropyEvent
            << "[FileDock] 熵值计算完成, panel="
            << panel.panelNameText.toStdString()
            << ", successCount="
            << successCount
            << ", failCount="
            << failedLines.size()
            << eol;
        return;
    }
    if (selectedAction == hexAction || selectedAction == peAction)
    {
        if (!kFirstPath.isEmpty() && QFileInfo(kFirstPath).isFile())
        {
            showFileDetailDialog(kFirstPath);
        }
        return;
    }
    if (selectedAction == mappedProcessScanAction)
    {
        openMappedProcessScanWindow(kMenuPaths);
        return;
    }
}

#include "FileDock.Support.h"

using namespace ksword::ui::file_dock;

void FileDock::refreshDriveCombo(FilePanelWidgets& panel)
{
    if (panel.driveCombo == nullptr)
    {
        return;
    }

    const QSignalBlocker kBlocker(panel.driveCombo);
    panel.driveCombo->clear();

    const QFileInfoList kDriveList = QDir::drives();
    int selectedIndex = -1;
    for (const QFileInfo& driveInfo : kDriveList)
    {
        const QString kRootPath = QDir::toNativeSeparators(driveInfo.absoluteFilePath());
        QString displayText = kRootPath;
        if (displayText.endsWith(QDir::separator()))
        {
            displayText.chop(1);
        }
        panel.driveCombo->addItem(displayText, kRootPath);

        if (!panel.currentPath.isEmpty()
            && panel.currentPath.startsWith(driveInfo.absoluteFilePath(), Qt::CaseInsensitive))
        {
            selectedIndex = panel.driveCombo->count() - 1;
        }
    }

    if (selectedIndex >= 0)
    {
        panel.driveCombo->setCurrentIndex(selectedIndex);
    }
}

void FileDock::applyReadModeToPanel(FilePanelWidgets& panel)
{
    if (panel.fileView == nullptr || panel.compactFileView == nullptr || panel.fileViewStack == nullptr)
    {
        return;
    }

    if (currentModeIsManual(panel))
    {
        panel.fileView->setModel(panel.manualProxyModel);
        panel.fileView->setRootIndex(QModelIndex());
        panel.compactFileView->setModel(panel.manualProxyModel);
        panel.compactFileView->setModelColumn(0);
        panel.compactFileView->setRootIndex(QModelIndex());
        panel.showHiddenCheck->setEnabled(false);
        panel.showSystemCheck->setEnabled(false);
        if (panel.parserStatusLabel != nullptr)
        {
            const ManualParseBackend kBackend = manualParseBackendForPanel(panel);
            if (kBackend == ManualParseBackend::kManualFs)
            {
                const ks::file::ManualFsType kRequestedFsType =
                    requestedManualFsTypeForPanel(panel);
                panel.parserStatusLabel->setText(
                    kRequestedFsType == ks::file::ManualFsType::kUnknown
                    ? QStringLiteral("解析器: 手动解析")
                    : QStringLiteral("解析器: %1 (待解析)")
                        .arg(manualFsTypeToText(kRequestedFsType)));
            }
            else
            {
                panel.parserStatusLabel->setText(
                    QStringLiteral("解析器: %1 (待查询)")
                        .arg(parseBackendDisplayText(kBackend)));
            }
        }
    }
    else
    {
        panel.fileView->setModel(panel.proxyModel);
        panel.compactFileView->setModel(panel.proxyModel);
        panel.compactFileView->setModelColumn(0);
        panel.showHiddenCheck->setEnabled(true);
        panel.showSystemCheck->setEnabled(true);
        if (!panel.currentPath.isEmpty())
        {
            const QModelIndex kSourceRootIndex = panel.fsModel->setRootPath(panel.currentPath);
            const QModelIndex kProxyRootIndex = panel.proxyModel->mapFromSource(kSourceRootIndex);
            panel.fileView->setRootIndex(kProxyRootIndex);
            panel.compactFileView->setRootIndex(kProxyRootIndex);
        }
        if (panel.parserStatusLabel != nullptr)
        {
            panel.parserStatusLabel->setText(QStringLiteral("解析器: Windows API"));
        }
    }

    configureFileViewSelection(panel);
    panel.fileView->header()->setStretchLastSection(false);
    panel.fileView->header()->setSectionResizeMode(0, QHeaderView::Stretch);
    QItemSelectionModel* selectionModel = panel.fileView->selectionModel();
    QItemSelectionModel* compactSelectionModel = panel.compactFileView->selectionModel();
    panel.compactFileView->setSelectionModel(panel.fileView->selectionModel());
    if (compactSelectionModel != nullptr && compactSelectionModel != panel.fileView->selectionModel())
    {
        compactSelectionModel->deleteLater();
    }

    if (selectionModel != nullptr)
    {
        QObject::disconnect(selectionModel, nullptr, this, nullptr);
        connect(selectionModel, &QItemSelectionModel::selectionChanged, this, [this, &panel](const QItemSelection&, const QItemSelection&) {
            updatePanelStatus(panel);
        });
    }
}

void FileDock::configureFileViewSelection(FilePanelWidgets& panel)
{
    if (panel.fileView == nullptr)
    {
        return;
    }

    // Batch operations in the file panel, such as delete, copy, cut, and R0 delete, collect paths from selectedRows(0).
    // Therefore, whether on initial creation or after switching to a Windows API/manual parsed model, 'full row extended multi-selection' must be maintained.
    panel.fileView->setSelectionBehavior(QAbstractItemView::SelectRows);
    panel.fileView->setSelectionMode(QAbstractItemView::ExtendedSelection);
    panel.compactFileView->setSelectionBehavior(QAbstractItemView::SelectRows);
    panel.compactFileView->setSelectionMode(QAbstractItemView::ExtendedSelection);
}

void FileDock::recreateFileSystemModel(FilePanelWidgets& panel)
{
    if (panel.rootWidget == nullptr || panel.proxyModel == nullptr)
    {
        return;
    }

    // QFileSystemModel caches directory entry metadata; calling setRootPath() on the same path often does not re-read file sizes.
    // Rebuild the model on manual refresh to re-enumerate columns like size/mtime from disk, while the proxy model and view continue using the original object.
    QFileSystemModel* const kOldModel = panel.fsModel;
    panel.fsModel = new ReparseAwareFileSystemModel(panel.rootWidget);
    panel.fsModel->setReadOnly(false);
    panel.fsModel->setResolveSymlinks(true);
    panel.fsModel->setFilter(QDir::AllEntries | QDir::NoDotAndDotDot);
    panel.fsModel->setNameFilterDisables(false);
    panel.proxyModel->setSourceModel(panel.fsModel);

    connect(panel.fsModel, &QFileSystemModel::directoryLoaded, this, [this, &panel](const QString&) {
        updatePanelStatus(panel);
    });

    if (kOldModel != nullptr)
    {
        kOldModel->deleteLater();
    }
}

bool FileDock::reloadManualModel(FilePanelWidgets& panel, const bool showWarningMessage)
{
    if (panel.manualModel == nullptr || panel.currentPath.isEmpty())
    {
        return false;
    }

    std::vector<ks::file::ManualDirectoryEntry> entries;
    ks::file::ManualFsType fsType = ks::file::ManualFsType::kUnknown;
    QString errorText;
    QString sourceDetail;
    // usedWinApiFallback: Records whether manual NTFS parsing has fallen back to the Windows API.
    bool usedWinApiFallback = false;
    bool partialResult = false;
    QStringList suspiciousNames;
    const ManualParseBackend kParseBackend = manualParseBackendForPanel(panel);
    const bool kDriverMode = parseBackendIsKernel(kParseBackend);
    const QString kBackendText = parseBackendDisplayText(kParseBackend);
    const ks::file::ManualFsType kRequestedFsType = requestedManualFsTypeForPanel(panel);
    const int kRequestedReadMode = panel.readModeCombo != nullptr
        ? panel.readModeCombo->currentIndex()
        : 0;
    const bool kParseOk = runManualParseBackend(
        kParseBackend,
        panel.currentPath,
        kRequestedFsType,
        entries,
        fsType,
        errorText,
        usedWinApiFallback,
        partialResult,
        sourceDetail,
        suspiciousNames);

    panel.manualModel->removeRows(0, panel.manualModel->rowCount());
    panel.lastManualFsType = fsType;
    panel.manualRequestedFsType = kRequestedFsType;
    panel.manualRequestedReadMode = kRequestedReadMode;
    panel.manualResultPartial = partialResult;
    panel.manualSourceDetail = sourceDetail;
    panel.manualSuspiciousNames = suspiciousNames;
    if (!kParseOk)
    {
        // privilegePromptHandled: Prevents displaying manual resolution for generic errors when a privilege prompt has already been handled.
        const bool kPrivilegePromptHandled = ks::ui::promptForPrivilegeFailure(
            this,
            kDriverMode
                ? QStringLiteral("%1目录").arg(kBackendText)
                : QStringLiteral("读取原始文件系统数据"),
            errorText);
        panel.manualLoadedPath.clear();
        if (panel.parserStatusLabel != nullptr)
        {
            panel.parserStatusLabel->setText(
                QStringLiteral("解析器: %1失败").arg(kBackendText));
        }
        if (showWarningMessage && !kPrivilegePromptHandled)
        {
            QMessageBox::warning(
                this,
                QStringLiteral("%1失败").arg(kBackendText),
                QStringLiteral("路径: %1\n错误: %2")
                .arg(QDir::toNativeSeparators(panel.currentPath))
                .arg(errorText));
        }

        KLogEvent event;
        warn << event
            << "[FileDock] 目录解析失败, source="
            << parseBackendLogTag(kParseBackend)
            << ", panel="
            << panel.panelNameText.toStdString()
            << ", path="
            << QDir::toNativeSeparators(panel.currentPath).toStdString()
            << ", error="
            << errorText.toStdString()
            << eol;
        return false;
    }

    const QSet<QString> kSuspiciousNameSet = buildSuspiciousNameSet(suspiciousNames);
    // reparseProbeBudget: The allowed number of synchronous reparse point probes for this batch of backfill operations.
    int reparseProbeBudget = kMaxBatchReparseProbes;
    for (const ks::file::ManualDirectoryEntry& itemValue : entries)
    {
        QList<QStandardItem*> rowItems;
        rowItems.reserve(static_cast<int>(ManualModelColumn::kCount));

        QStandardItem* nameItem = new QStandardItem(itemValue.name);
        nameItem->setIcon(QApplication::style()->standardIcon(
            itemValue.isDirectory ? QStyle::SP_DirIcon : QStyle::SP_FileIcon));
        nameItem->setData(itemValue.absolutePath, Qt::UserRole);
        nameItem->setData(itemValue.isDirectory, Qt::UserRole + 1);
        rowItems.push_back(nameItem);

        QStandardItem* sizeItem = new QStandardItem(itemValue.isDirectory ? QStringLiteral("-") : formatSizeText(itemValue.sizeBytes));
        sizeItem->setData(static_cast<qulonglong>(itemValue.sizeBytes), Qt::UserRole);
        rowItems.push_back(sizeItem);

        QString typeText = itemValue.typeText;
        // Perform synchronous probing only within the quota; see the note for kMaxBatchReparseProbes.
        if (reparseProbeBudget > 0)
        {
            --reparseProbeBudget;
            const QString kReparseMarkerText =
                reparseKindMarkerForPath(itemValue.absolutePath);
            if (!kReparseMarkerText.isEmpty())
            {
                typeText = QStringLiteral("%1 / %2").arg(kReparseMarkerText, typeText);
            }
        }
        rowItems.push_back(new QStandardItem(typeText));
        rowItems.push_back(new QStandardItem(itemValue.modifiedTime.isValid()
            ? itemValue.modifiedTime.toString(QStringLiteral("yyyy-MM-dd HH:mm:ss"))
            : QStringLiteral("-")));
        rowItems.push_back(new QStandardItem(QDir::toNativeSeparators(itemValue.absolutePath)));
        rowItems.push_back(new QStandardItem(itemValue.isDirectory ? QStringLiteral("1") : QStringLiteral("0")));
        markSuspiciousRowIfNeeded(rowItems, itemValue.name, kSuspiciousNameSet);
        panel.manualModel->appendRow(rowItems);
    }

    if (panel.parserStatusLabel != nullptr)
    {
        // After a manual link failure, if the system has rolled back to the Windows API, the true source must be explicitly displayed to avoid misleading the UI.
        if (!sourceDetail.isEmpty())
        {
            QString statusText = QStringLiteral("解析器: %1").arg(sourceDetail);
            if (!suspiciousNames.isEmpty())
            {
                statusText += QStringLiteral("；疑似隐藏项 %1 个")
                    .arg(suspiciousNames.size());
            }
            panel.parserStatusLabel->setText(statusText);
        }
        else if (usedWinApiFallback)
        {
            panel.parserStatusLabel->setText(
                QStringLiteral("解析器: Windows API 回退 (%1)")
                .arg(manualFsTypeToText(fsType)));
        }
        else
        {
            panel.parserStatusLabel->setText(
                QStringLiteral("解析器: %1 (手动)")
                .arg(manualFsTypeToText(fsType)));
        }
    }
    panel.manualLoadedPath = panel.currentPath;

    KLogEvent event;
    info << event
        << "[FileDock] 目录解析完成, source="
        << parseBackendLogTag(kParseBackend)
        << ", panel="
        << panel.panelNameText.toStdString()
        << ", partial="
        << (partialResult ? "true" : "false")
        << ", fsType="
        << manualFsTypeToText(fsType).toStdString()
        << ", rows="
        << entries.size()
        << ", path="
        << QDir::toNativeSeparators(panel.currentPath).toStdString()
        << eol;
    return true;
}

void FileDock::requestAsyncManualReload(FilePanelWidgets& panel, const bool showWarningMessage)
{
    if (panel.manualModel == nullptr || panel.currentPath.isEmpty())
    {
        return;
    }

    // requestedPath: Records the target path for this call to avoid reading changed values in asynchronous flows.
    const QString kRequestedPath = panel.currentPath;
    const ks::file::ManualFsType kRequestedFsType = requestedManualFsTypeForPanel(panel);
    const int kRequestedReadMode = panel.readModeCombo != nullptr
        ? panel.readModeCombo->currentIndex()
        : 0;
    const ManualParseBackend kParseBackend = manualParseBackendForPanel(panel);
    const bool kDriverMode = parseBackendIsKernel(kParseBackend);
    const QString kBackendText = parseBackendDisplayText(kParseBackend);

    // If the path is already loaded and no task is currently running, reuse the result directly to avoid meaningless re-parsing.
    if (!panel.manualParseInProgress
        && panel.manualLoadedPath.compare(kRequestedPath, Qt::CaseInsensitive) == 0
        && panel.manualRequestedFsType == kRequestedFsType
        && panel.manualRequestedReadMode == kRequestedReadMode)
    {
        return;
    }

    panel.manualRequestedFsType = kRequestedFsType;
    panel.manualRequestedReadMode = kRequestedReadMode;

    // If a background task is already running, register as pending only when the target request changes.
    // The comparison criterion must include the read method: using a different parsing method for the same directory
    // yields completely different data sets (WinAPI view / pure MFT view / IRP bypass view). Comparing only the path
    // would cause requests with a changed method to be treated as duplicates and discarded, leaving old backend
    // results in the table while the dropdown shows the new method—appearing as if 'nothing happened after switching'.
    if (panel.manualParseInProgress)
    {
        const bool kSamePathRunning =
            (panel.manualParsingPath.compare(kRequestedPath, Qt::CaseInsensitive) == 0)
            && (panel.manualParsingReadMode == kRequestedReadMode);
        if (kSamePathRunning)
        {
            panel.manualParsePendingShowWarning =
                panel.manualParsePendingShowWarning || showWarningMessage;
            return;
        }

        panel.manualParsePending = true;
        panel.manualParsePendingShowWarning = panel.manualParsePendingShowWarning || showWarningMessage;

        {
            KLogEvent event;
            dbg << event
                << "[FileDock] 手动解析任务排队, panel="
                << panel.panelNameText.toStdString()
                << ", runningPath="
                << QDir::toNativeSeparators(panel.manualParsingPath).toStdString()
                << ", pendingPath="
                << QDir::toNativeSeparators(kRequestedPath).toStdString()
                << eol;
        }
        return;
    }

    panel.manualParseInProgress = true;
    panel.manualParsePending = false;
    panel.manualParsePendingShowWarning = false;
    panel.manualParseRequestSerial += 1;
    panel.manualParsingPath = kRequestedPath;
    panel.manualParsingReadMode = kRequestedReadMode;

    // Log request context: used to validate whether results have expired during back-thread callbacks.
    const int kRequestSerial = panel.manualParseRequestSerial;
    const QString kRequestPath = kRequestedPath;
    const QString kPanelNameText = panel.panelNameText;
    const bool kLeftPanelRequest = (&panel == &leftPanel_);

    // Tiled progress bar: R3 raw parsing and R0 kernel enumeration share the same asynchronous backfill mechanism.
    const QString kParserTaskText = QStringLiteral(" ") + kBackendText;
    const int kProgressPid = kPro.add(this, "文件", (kPanelNameText + kParserTaskText).toStdString());
    kPro.set(kProgressPid, "准备解析目录", 0, 5.0f);

    if (panel.parserStatusLabel != nullptr)
    {
        panel.parserStatusLabel->setText(
            QStringLiteral("解析器: %1中...").arg(kBackendText));
    }
    if (panel.readModeCombo != nullptr)
    {
        panel.readModeCombo->setEnabled(false);
    }

    {
        KLogEvent event;
        info << event
            << "[FileDock] 启动异步平铺解析, source="
            << parseBackendLogTag(kParseBackend)
            << ", panel="
            << kPanelNameText.toStdString()
            << ", path="
            << QDir::toNativeSeparators(kRequestPath).toStdString()
            << ", requestSerial="
            << kRequestSerial
            << eol;
    }

    QPointer<FileDock> safeThis(this);
    std::thread([safeThis, kLeftPanelRequest, kRequestPath, kRequestedFsType, kRequestedReadMode, kParseBackend, kDriverMode, kBackendText, kPanelNameText, showWarningMessage, kRequestSerial, kProgressPid]() {
        kPro.set(
            kProgressPid,
            (kBackendText + QStringLiteral("目录中")).toStdString(),
            0,
            35.0f);

        std::vector<ks::file::ManualDirectoryEntry> parsedEntries;
        ks::file::ManualFsType parsedFsType = ks::file::ManualFsType::kUnknown;
        QString parseErrorText;
        // usedWinApiFallback: Records whether background parsing has fallen back to the Windows API, enabling correct UI status display.
        bool usedWinApiFallback = false;
        bool partialResult = false;
        QString sourceDetail;
        QStringList suspiciousNames;
        const bool kParseOk = runManualParseBackend(
            kParseBackend,
            kRequestPath,
            kRequestedFsType,
            parsedEntries,
            parsedFsType,
            parseErrorText,
            usedWinApiFallback,
            partialResult,
            sourceDetail,
            suspiciousNames);

        kPro.set(kProgressPid, kParseOk ? "生成目录列表中" : "解析失败，整理错误信息", 0, 78.0f);

        if (safeThis.isNull())
        {
            kPro.set(kProgressPid, "界面已关闭", 0, 100.0f);
            return;
        }

        const bool kInvokeOk = QMetaObject::invokeMethod(
            safeThis.data(),
            [safeThis,
             kLeftPanelRequest,
             kRequestPath,
             kRequestedFsType,
             kRequestedReadMode,
             kParseBackend,
             kDriverMode,
             kBackendText,
             kPanelNameText,
             showWarningMessage,
             kRequestSerial,
             kProgressPid,
             kParseOk,
             parsedEntries = std::move(parsedEntries),
             parsedFsType,
             parseErrorText,
             usedWinApiFallback,
             partialResult,
             sourceDetail,
             suspiciousNames]() mutable {
                if (safeThis.isNull())
                {
                    kPro.set(kProgressPid, "界面已关闭", 0, 100.0f);
                    return;
                }

                FilePanelWidgets& targetPanel = kLeftPanelRequest ? safeThis->leftPanel_ : safeThis->rightPanel_;
                if (targetPanel.manualParseRequestSerial != kRequestSerial)
                {
                    // Discard expired results immediately to prevent slow tasks from overwriting data for new paths.
                    // Clear the running status only if this batch of results indeed belongs to the current run:
                    // A path mismatch indicates the panel is already running another parse; clearing it would incorrectly signal idle status.
                    if (targetPanel.manualParsingPath.compare(kRequestPath, Qt::CaseInsensitive) == 0)
                    {
                        targetPanel.manualParseInProgress = false;
                        targetPanel.manualParsingPath.clear();
                    }
                    // Decouple the dropdown's availability from its running state; restore unconditionally.
                    // It was disabled at the start of this request and must be re-enabled once the request reaches
                    //its end (whether accepted or discarded). Placing this logic in the upper conditional branch
                    // means that if the path does not match, no one will ever re-enable it, resulting in the
                    // behavior where 'after selecting a read mode, the dropdown becomes completely unclickable'.
                    if (targetPanel.readModeCombo != nullptr &&
                        !targetPanel.manualParseInProgress)
                    {
                        targetPanel.readModeCombo->setEnabled(true);
                    }

                    {
                        KLogEvent event;
                        warn << event
                            << "[FileDock] 丢弃过期平铺解析结果, source="
                            << parseBackendLogTag(kParseBackend)
                            << ", panel="
                            << kPanelNameText.toStdString()
                            << ", path="
                            << QDir::toNativeSeparators(kRequestPath).toStdString()
                            << ", requestSerial="
                            << kRequestSerial
                            << ", currentSerial="
                            << targetPanel.manualParseRequestSerial
                            << eol;
                    }

                    kPro.set(kProgressPid, "结果过期已忽略", 0, 100.0f);

                    if (!targetPanel.manualParseInProgress && targetPanel.manualParsePending)
                    {
                        const bool kPendingShowWarning = targetPanel.manualParsePendingShowWarning;
                        targetPanel.manualParsePending = false;
                        targetPanel.manualParsePendingShowWarning = false;
                        safeThis->requestAsyncManualReload(targetPanel, kPendingShowWarning);
                    }
                    return;
                }

                const auto kParsedEntriesSnapshot =
                    std::make_shared<std::vector<ks::file::ManualDirectoryEntry>>(
                        std::move(parsedEntries));
                const auto kCommitSnapshot =
                    [safeThis,
                     kLeftPanelRequest,
                     kRequestPath,
                     kRequestedFsType,
                     kRequestedReadMode,
                     kParseBackend,
                     kDriverMode,
                     kBackendText,
                     kPanelNameText,
                     showWarningMessage,
                     kRequestSerial,
                     kProgressPid,
                     kParseOk,
                     kParsedEntriesSnapshot,
                     parsedFsType,
                     parseErrorText,
                     usedWinApiFallback,
                     partialResult,
                     sourceDetail,
                     suspiciousNames]()
                {
                    if (safeThis.isNull())
                    {
                        kPro.set(kProgressPid, "界面已关闭", 0, 100.0f);
                        return;
                    }

                    FilePanelWidgets& commitPanel =
                        kLeftPanelRequest ? safeThis->leftPanel_ : safeThis->rightPanel_;
                    if (commitPanel.manualParseRequestSerial != kRequestSerial)
                    {
                        return;
                    }

                    commitPanel.manualParseInProgress = false;
                    commitPanel.manualParsingPath.clear();
                    commitPanel.manualRequestedFsType = kRequestedFsType;
                    commitPanel.manualRequestedReadMode = kRequestedReadMode;
                    commitPanel.manualResultPartial = partialResult;
                    commitPanel.manualSourceDetail = sourceDetail;
                    commitPanel.manualSuspiciousNames = suspiciousNames;
                    if (commitPanel.readModeCombo != nullptr)
                    {
                        commitPanel.readModeCombo->setEnabled(true);
                    }

                    commitPanel.manualModel->setRowCount(0);
                    commitPanel.lastManualFsType = parsedFsType;

                    if (!kParseOk)
                    {
                        // Remember the path even on failure to prevent filter/sort operations from triggering continuous retries.
                        commitPanel.manualLoadedPath = kRequestPath;
                        if (commitPanel.parserStatusLabel != nullptr)
                        {
                            commitPanel.parserStatusLabel->setText(
                                QStringLiteral("解析器: %1失败").arg(kBackendText));
                        }

                        // Raw file system enumeration requires direct volume device access; a standard token returns ERROR_ACCESS_DENIED.
                        // Async completion callbacks must integrate with the same privilege restoration as the synchronous entry point; otherwise, mode switching leaves only an empty table.
                        const bool kPrivilegePromptHandled =
                            ks::ui::promptForPrivilegeFailure(
                                safeThis.data(),
                                kDriverMode
                                ? QStringLiteral("%1目录").arg(kBackendText)
                                : QStringLiteral("读取原始文件系统数据"),
                                parseErrorText);
                        if (showWarningMessage && !kPrivilegePromptHandled)
                        {
                            QMessageBox::warning(
                                safeThis.data(),
                                QStringLiteral("%1失败").arg(kBackendText),
                                QStringLiteral("路径: %1\n错误: %2")
                                .arg(QDir::toNativeSeparators(kRequestPath))
                                .arg(parseErrorText));
                        }

                        KLogEvent event;
                        warn << event
                            << "[FileDock] 异步平铺解析失败, source="
                            << parseBackendLogTag(kParseBackend)
                            << ", panel="
                            << kPanelNameText.toStdString()
                            << ", path="
                            << QDir::toNativeSeparators(kRequestPath).toStdString()
                            << ", error="
                            << parseErrorText.toStdString()
                            << eol;
                    }
                    else
                    {
                        // Batch model fill-back:
                        // - No longer block manualModel signals to prevent the proxy from failing to detect new rows, which causes 'log shows rows but view is blank'.
                        // - Reduce UI overhead during batch inserts by temporarily disabling view repainting.
                        if (commitPanel.fileView != nullptr)
                        {
                            commitPanel.fileView->setUpdatesEnabled(false);
                            commitPanel.compactFileView->setUpdatesEnabled(false);
                        }
                        const QSet<QString> kSuspiciousNameSet =
                            buildSuspiciousNameSet(suspiciousNames);
                        // reparseProbeBudget: The allowed number of synchronous reparse point probes for this batch of backfill operations.
                        int reparseProbeBudget = kMaxBatchReparseProbes;
                        for (const ks::file::ManualDirectoryEntry& itemValue : *kParsedEntriesSnapshot)
                        {
                            QList<QStandardItem*> rowItems;
                            rowItems.reserve(static_cast<int>(ManualModelColumn::kCount));

                            QStandardItem* nameItem = new QStandardItem(itemValue.name);
                            nameItem->setIcon(QApplication::style()->standardIcon(
                                itemValue.isDirectory ? QStyle::SP_DirIcon : QStyle::SP_FileIcon));
                            nameItem->setData(itemValue.absolutePath, Qt::UserRole);
                            nameItem->setData(itemValue.isDirectory, Qt::UserRole + 1);
                            rowItems.push_back(nameItem);

                            QStandardItem* sizeItem = new QStandardItem(
                                itemValue.isDirectory
                                ? QStringLiteral("-")
                                : formatSizeText(itemValue.sizeBytes));
                            sizeItem->setData(
                                static_cast<qulonglong>(itemValue.sizeBytes),
                                Qt::UserRole);
                            rowItems.push_back(sizeItem);

                            QString typeText = itemValue.typeText;
                            // Perform synchronous probing only within the quota; see the note for kMaxBatchReparseProbes.
                            // This path is critical: R0/IRP read mode can fill in tens of thousands of lines at once;
                            // performing Win32 queries line-by-line would block the UI thread for several seconds.
                            if (reparseProbeBudget > 0)
                            {
                                --reparseProbeBudget;
                                const QString kReparseMarkerText =
                                    reparseKindMarkerForPath(itemValue.absolutePath);
                                if (!kReparseMarkerText.isEmpty())
                                {
                                    typeText = QStringLiteral("%1 / %2")
                                        .arg(kReparseMarkerText, typeText);
                                }
                            }
                            rowItems.push_back(new QStandardItem(typeText));
                            rowItems.push_back(new QStandardItem(
                                itemValue.modifiedTime.isValid()
                                ? itemValue.modifiedTime.toString(
                                    QStringLiteral("yyyy-MM-dd HH:mm:ss"))
                                : QStringLiteral("-")));
                            rowItems.push_back(new QStandardItem(
                                QDir::toNativeSeparators(itemValue.absolutePath)));
                            rowItems.push_back(new QStandardItem(
                                itemValue.isDirectory
                                ? QStringLiteral("1")
                                : QStringLiteral("0")));
                            markSuspiciousRowIfNeeded(
                                rowItems, itemValue.name, kSuspiciousNameSet);
                            commitPanel.manualModel->appendRow(rowItems);
                        }
                        if (commitPanel.manualProxyModel != nullptr)
                        {
                            commitPanel.manualProxyModel->invalidate();
                        }
                        if (commitPanel.fileView != nullptr)
                        {
                            commitPanel.fileView->setRootIndex(QModelIndex());
                            commitPanel.compactFileView->setRootIndex(QModelIndex());
                            commitPanel.fileView->setUpdatesEnabled(true);
                            commitPanel.compactFileView->setUpdatesEnabled(true);
                        }

                        if (commitPanel.parserStatusLabel != nullptr)
                        {
                            // Asynchronous and synchronous paths follow the same display rules and explicitly indicate the true data source.
                            if (!sourceDetail.isEmpty())
                            {
                                QString statusText =
                                    QStringLiteral("解析器: %1").arg(sourceDetail);
                                if (!suspiciousNames.isEmpty())
                                {
                                    statusText += QStringLiteral("；疑似隐藏项 %1 个")
                                        .arg(suspiciousNames.size());
                                }
                                commitPanel.parserStatusLabel->setText(statusText);
                            }
                            else if (usedWinApiFallback)
                            {
                                commitPanel.parserStatusLabel->setText(
                                    QStringLiteral("解析器: Windows API 回退 (%1)")
                                    .arg(manualFsTypeToText(parsedFsType)));
                            }
                            else
                            {
                                commitPanel.parserStatusLabel->setText(
                                    QStringLiteral("解析器: %1 (手动)")
                                    .arg(manualFsTypeToText(parsedFsType)));
                            }
                        }
                        commitPanel.manualLoadedPath = kRequestPath;

                        KLogEvent event;
                        info << event
                            << "[FileDock] 异步平铺解析完成, source="
                            << parseBackendLogTag(kParseBackend)
                            << ", panel="
                            << kPanelNameText.toStdString()
                            << ", fsType="
                            << manualFsTypeToText(parsedFsType).toStdString()
                            << ", rows="
                            << kParsedEntriesSnapshot->size()
                            << ", partial="
                            << (partialResult ? "true" : "false")
                            << ", path="
                            << QDir::toNativeSeparators(kRequestPath).toStdString()
                            << eol;
                    }

                    // After model backfill, reapply filter/sort to immediately update the view to the current conditions.
                    safeThis->applyPanelFilterAndSort(commitPanel);
                    kPro.set(
                        kProgressPid,
                        (kBackendText +
                            (kParseOk
                                ? QStringLiteral("完成")
                                : QStringLiteral("失败"))).toStdString(),
                        0,
                        100.0f);

                    // If the user switched directories during parsing, immediately execute the pending request upon completion.
                    if (!commitPanel.manualParseInProgress && commitPanel.manualParsePending)
                    {
                        const bool kPendingShowWarning =
                            commitPanel.manualParsePendingShowWarning;
                        commitPanel.manualParsePending = false;
                        commitPanel.manualParsePendingShowWarning = false;
                        safeThis->requestAsyncManualReload(commitPanel, kPendingShowWarning);
                    }
                };

                const QString kCommitKey = kLeftPanelRequest
                    ? QStringLiteral("file-manual-model-left")
                    : QStringLiteral("file-manual-model-right");
                if (ks::ui::deferItemViewUiCommitIfContextMenuOpen(
                    safeThis.data(),
                    kCommitKey,
                    { targetPanel.fileView },
                    kCommitSnapshot))
                {
                    return;
                }
                kCommitSnapshot();
            },
            Qt::QueuedConnection);

        if (!kInvokeOk)
        {
            kPro.set(kProgressPid, "回调失败", 0, 100.0f);
        }
    }).detach();
}

bool FileDock::currentModeIsManual(const FilePanelWidgets& panel) const
{
    return panel.readModeCombo != nullptr && panel.readModeCombo->currentIndex() >= 1;
}

bool FileDock::currentModeUsesDriver(const FilePanelWidgets& panel) const
{
    // R0 driver parsing and R0 IRP parsing are both handled by the kernel; other tiling modes remain completed in R3.
    return parseBackendIsKernel(manualParseBackendForPanel(panel));
}

ks::file::ManualFsType FileDock::requestedManualFsTypeForPanel(const FilePanelWidgets& panel) const
{
    if (panel.readModeCombo == nullptr)
    {
        return ks::file::ManualFsType::kUnknown;
    }

    switch (panel.readModeCombo->currentIndex())
    {
    case 3:
        return ks::file::ManualFsType::kNtfs;
    case 4:
        return ks::file::ManualFsType::kFat32;
    case 5:
        return ks::file::ManualFsType::kExFat;
    case 6:
        // Pure MFT scanning only applies to NTFS; force parsing as NTFS.
        return ks::file::ManualFsType::kNtfs;
    default:
        return ks::file::ManualFsType::kUnknown;
    }
}

FileDock::ManualParseBackend FileDock::manualParseBackendForPanel(
    const FilePanelWidgets& panel) const
{
    if (panel.readModeCombo == nullptr)
    {
        return ManualParseBackend::kWindowsApi;
    }

    switch (panel.readModeCombo->currentIndex())
    {
    case 0:
        return ManualParseBackend::kWindowsApi;
    case 2:
        return ManualParseBackend::kR0Driver;
    case 6:
        return ManualParseBackend::kMftStrict;
    case 7:
        return ManualParseBackend::kR0Irp;
    default:
        // 1/3/4/5 are all R3 manual parsing; the difference lies only in the forced file system type.
        return ManualParseBackend::kManualFs;
    }
}

bool FileDock::parseBackendIsKernel(const ManualParseBackend backend)
{
    return backend == ManualParseBackend::kR0Driver ||
        backend == ManualParseBackend::kR0Irp;
}

QString FileDock::parseBackendDisplayText(const ManualParseBackend backend)
{
    switch (backend)
    {
    case ManualParseBackend::kR0Driver:
        return QStringLiteral("R0 驱动解析");
    case ManualParseBackend::kR0Irp:
        return QStringLiteral("R0 IRP 解析");
    case ManualParseBackend::kMftStrict:
        return QStringLiteral("纯 MFT 解析");
    case ManualParseBackend::kManualFs:
        return QStringLiteral("手动解析");
    case ManualParseBackend::kWindowsApi:
    default:
        return QStringLiteral("Windows API");
    }
}

const char* FileDock::parseBackendLogTag(const ManualParseBackend backend)
{
    switch (backend)
    {
    case ManualParseBackend::kR0Driver:
        return "R0";
    case ManualParseBackend::kR0Irp:
        return "R0-IRP";
    case ManualParseBackend::kMftStrict:
        return "R3-mft";
    case ManualParseBackend::kManualFs:
        return "R3-manual";
    case ManualParseBackend::kWindowsApi:
    default:
        return "WinAPI";
    }
}

bool FileDock::runManualParseBackend(
    const ManualParseBackend backend,
    const QString& pathText,
    const ks::file::ManualFsType requestedFsType,
    std::vector<ks::file::ManualDirectoryEntry>& entriesOut,
    ks::file::ManualFsType& fsTypeOut,
    QString& errorTextOut,
    bool& usedWinApiFallbackOut,
    bool& partialOut,
    QString& sourceDetailOut,
    QStringList& suspiciousNamesOut)
{
    usedWinApiFallbackOut = false;
    partialOut = false;
    sourceDetailOut.clear();
    suspiciousNamesOut.clear();

    switch (backend)
    {
    case ManualParseBackend::kR0Driver:
        return ks::file::DriverFileSystemParser::enumerateDirectory(
            pathText,
            entriesOut,
            fsTypeOut,
            errorTextOut,
            &partialOut,
            &sourceDetailOut);

    case ManualParseBackend::kR0Irp:
    {
        ks::file::IrpScanDiagnostics diagnostics;
        const bool kParseOk = ks::file::IrpFileSystemParser::enumerateDirectory(
            pathText,
            entriesOut,
            fsTypeOut,
            errorTextOut,
            &partialOut,
            &sourceDetailOut,
            &diagnostics);
        if (kParseOk)
        {
            suspiciousNamesOut = diagnostics.bypassOnlyNames;
        }
        return kParseOk;
    }

    case ManualParseBackend::kMftStrict:
    {
        ks::file::MftScanDiagnostics diagnostics;
        fsTypeOut = ks::file::ManualFsType::kNtfs;
        const bool kParseOk = ks::file::ManualFileSystemParser::enumerateDirectoryByMft(
            pathText,
            entriesOut,
            errorTextOut,
            &diagnostics);
        if (!kParseOk)
        {
            return false;
        }
        suspiciousNamesOut = diagnostics.mftOnlyNames;
        sourceDetailOut = diagnostics.comparisonAvailable
            ? QStringLiteral("纯 MFT 解析；条目=%1；目录枚举视图=%2；仅 MFT 可见=%3")
                .arg(diagnostics.mftEntryCount)
                .arg(diagnostics.winApiEntryCount)
                .arg(diagnostics.mftOnlyNames.size())
            : QStringLiteral("纯 MFT 解析；条目=%1；未取得目录枚举对照")
                .arg(diagnostics.mftEntryCount);
        return true;
    }

    case ManualParseBackend::kManualFs:
    case ManualParseBackend::kWindowsApi:
    default:
        return ks::file::ManualFileSystemParser::enumerateDirectory(
            pathText,
            entriesOut,
            fsTypeOut,
            errorTextOut,
            &usedWinApiFallbackOut,
            requestedFsType);
    }
}

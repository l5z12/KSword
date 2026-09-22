#include "ProcessDetailWindow.InternalCommon.h"

using namespace process_detail_window_internal;

// ============================================================
// ProcessDetailWindow.Module.cpp
// Purpose:
// - Responsible for asynchronous module page refresh, module table construction, and executing module right-click actions.
// - Focus on the logic for 'module information and module-related actions'.
// ============================================================

void ProcessDetailWindow::requestAsyncModuleRefresh(const bool forceRefresh)
{
    // Module refresh entry log: records the force-refresh flag and the current refresh state.
    KLogEvent requestModuleRefreshEvent;
    info << requestModuleRefreshEvent
        << "[ProcessDetailWindow] requestAsyncModuleRefresh: forceRefresh="
        << (forceRefresh ? "true" : "false")
        << ", refreshing="
        << (moduleRefreshing_ ? "true" : "false")
        << ", pid="
        << baseRecord_.pid
        << eol;

    // Prevent result disorder caused by concurrent refreshes.
    if (moduleRefreshing_)
    {
        if (!forceRefresh)
        {
            return;
        }
        // When force=true, do not stack tasks; only log and return immediately.
        KLogEvent logEvent;
        warn << logEvent
            << "[ProcessDetailWindow] 忽略模块刷新请求：已有刷新任务在运行, pid="
            << baseRecord_.pid
            << eol;
        return;
    }

    // Any real request entering the module refresh function is treated as the module page being loaded on demand.
    // After the user manually clicks refresh, switching back to the module page will not trigger another automatic initial refresh.
    moduleInitialRefreshStarted_ = true;

    const std::uint32_t kPidValue = baseRecord_.pid;
    const std::uint64_t kExpectedCreationTime100ns = baseRecord_.creationTime100ns;
    const bool kIncludeSignatureCheck = (signatureCheckBox_ != nullptr) && signatureCheckBox_->isChecked();
    const bool kFirstRefresh = !firstModuleRefreshDone_;

    KLogEvent requestModuleRefreshConfigEvent;
    dbg << requestModuleRefreshConfigEvent
        << "[ProcessDetailWindow] requestAsyncModuleRefresh: includeSignatureCheck="
        << (kIncludeSignatureCheck ? "true" : "false")
        << ", firstRefresh="
        << (kFirstRefresh ? "true" : "false")
        << eol;

    // Use a progress bar for the first module refresh to satisfy the requirement of making slow initial operations visible.
    if (kFirstRefresh)
    {
        if (moduleRefreshProgressPid_ <= 0)
        {
            moduleRefreshProgressPid_ = kPro.addReusable(
                this,
                "模块列表首次刷新",
                "准备读取模块与线程信息...");
        }
        kPro.set(moduleRefreshProgressPid_, "开始读取模块快照...", 10, 0.10f);
    }

    moduleRefreshing_ = true;
    const std::uint64_t kLocalTicket = ++moduleRefreshTicket_;
    updateModuleStatusLabel("● 正在刷新模块列表...", true);

    KLogEvent logEvent;
    info << logEvent
        << "[ProcessDetailWindow] 模块刷新开始, pid=" << kPidValue
        << ", includeSignature=" << (kIncludeSignatureCheck ? "true" : "false")
        << ", ticket=" << kLocalTicket
        << eol;

    QPointer<ProcessDetailWindow> guard(this);
    QRunnable* backgroundTask = QRunnable::create([guard, kLocalTicket, kPidValue, kExpectedCreationTime100ns, kIncludeSignatureCheck, kFirstRefresh]() {
        const auto kStartTime = std::chrono::steady_clock::now();
        ModuleRefreshResult refreshResult{};
        refreshResult.includeSignatureCheck = kIncludeSignatureCheck;
        refreshResult.moduleSnapshot = ks::process::enumerateProcessModulesAndThreadsIfIdentityMatches(
            kPidValue,
            kExpectedCreationTime100ns,
            kIncludeSignatureCheck);
        refreshResult.elapsedMs = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - kStartTime).count());

        if (guard == nullptr)
        {
            KLogEvent requestModuleRefreshGuardEvent;
            warn << requestModuleRefreshGuardEvent
                << "[ProcessDetailWindow] requestAsyncModuleRefresh: guard失效，后台结果丢弃, pid="
                << kPidValue
                << eol;
            return;
        }

        if (kFirstRefresh && guard->moduleRefreshProgressPid_ > 0)
        {
            kPro.set(guard->moduleRefreshProgressPid_, "后台读取完成，准备更新界面...", 85, 0.85f);
        }

        QMetaObject::invokeMethod(guard, [guard, kLocalTicket, refreshResult]() {
            if (guard == nullptr)
            {
                return;
            }
            if (kLocalTicket < guard->moduleRefreshTicket_)
            {
                KLogEvent requestModuleRefreshOutdatedEvent;
                dbg << requestModuleRefreshOutdatedEvent
                    << "[ProcessDetailWindow] requestAsyncModuleRefresh: 过期ticket结果丢弃, localTicket="
                    << kLocalTicket
                    << ", latestTicket="
                    << guard->moduleRefreshTicket_
                    << eol;
                guard->moduleRefreshing_ = false;
                return;
            }
            guard->applyModuleRefreshResult(refreshResult);
            guard->moduleRefreshing_ = false;
        }, Qt::QueuedConnection);
    });

    backgroundTask->setAutoDelete(true);
    QThreadPool::globalInstance()->start(backgroundTask);
}

void ProcessDetailWindow::applyModuleRefreshResult(const ModuleRefreshResult& refreshResult)
{
    // Log for applying module refresh results: outputs the number of modules, threads, and elapsed time.
    KLogEvent applyModuleResultEvent;
    info << applyModuleResultEvent
        << "[ProcessDetailWindow] applyModuleRefreshResult: modules="
        << refreshResult.moduleSnapshot.modules.size()
        << ", threads="
        << refreshResult.moduleSnapshot.threads.size()
        << ", elapsedMs="
        << refreshResult.elapsedMs
        << eol;

    // Overwrite module cache and rebuild the table.
    moduleRecords_ = refreshResult.moduleSnapshot.modules;
    rebuildModuleTable();

    const QString kDiagnosticText = QString::fromStdString(refreshResult.moduleSnapshot.diagnosticText);

    // Update status label: display elapsed time, module count, and thread count.
    QString statusText = QString("● 刷新完成 %1 ms | 模块:%2 线程:%3")
        .arg(refreshResult.elapsedMs)
        .arg(refreshResult.moduleSnapshot.modules.size())
        .arg(refreshResult.moduleSnapshot.threads.size());
    if (!kDiagnosticText.trimmed().isEmpty())
    {
        statusText += QStringLiteral(
            " | 存在诊断；详情已写入日志。");
    }
    updateModuleStatusLabel(statusText, false);
    if (refreshResult.moduleSnapshot.modules.empty())
    {
        moduleStatusLabel_->setStyleSheet(buildStateLabelStyle(statusErrorColor(), 700));
    }

    // Hide the corresponding progress task card after the first refresh completes.
    if (!firstModuleRefreshDone_)
    {
        firstModuleRefreshDone_ = true;
        if (moduleRefreshProgressPid_ > 0)
        {
            kPro.set(moduleRefreshProgressPid_, "模块首次刷新完成", 100, 1.0f);
        }
    }

    KLogEvent logEvent;
    info << logEvent
        << "[ProcessDetailWindow] 模块刷新完成, pid=" << baseRecord_.pid
        << ", elapsedMs=" << refreshResult.elapsedMs
        << ", moduleCount=" << refreshResult.moduleSnapshot.modules.size()
        << ", threadCount=" << refreshResult.moduleSnapshot.threads.size()
        << ", includeSignature=" << (refreshResult.includeSignatureCheck ? "true" : "false")
        << ", diagnostic=" << refreshResult.moduleSnapshot.diagnosticText
        << eol;

    // Output an additional warning log when the module count is 0 to facilitate rapid identification of permission or cross-architecture issues.
    if (refreshResult.moduleSnapshot.modules.empty())
    {
        KLogEvent warnEvent;
        warn << warnEvent
            << "[ProcessDetailWindow] 模块列表为空, pid=" << baseRecord_.pid
            << ", diagnostic=" << refreshResult.moduleSnapshot.diagnosticText
            << eol;
    }
}

void ProcessDetailWindow::rebuildModuleTable()
{
    // Rebuild module table log: used to measure UI list scale.
    KLogEvent rebuildModuleTableEvent;
    dbg << rebuildModuleTableEvent
        << "[ProcessDetailWindow] rebuildModuleTable: recordCount="
        << moduleRecords_.size()
        << eol;

    moduleTable_->clear();

    for (const ks::process::ProcessModuleRecord& moduleRecord : moduleRecords_)
    {
        QTreeWidgetItem* rowItem = new QTreeWidgetItem();
        rowItem->setText(toModuleColumnIndex(ModuleColumn::kPath), QString::fromStdString(moduleRecord.modulePath));
        rowItem->setText(toModuleColumnIndex(ModuleColumn::kSize), formatModuleSizeText(moduleRecord.moduleSizeBytes));
        rowItem->setText(toModuleColumnIndex(ModuleColumn::kSignature), QString::fromStdString(moduleRecord.signatureState));
        rowItem->setText(toModuleColumnIndex(ModuleColumn::kEntryOffset), formatHexText(moduleRecord.entryPointRva));
        rowItem->setText(toModuleColumnIndex(ModuleColumn::kState), QString::fromStdString(moduleRecord.runningState));
        rowItem->setText(toModuleColumnIndex(ModuleColumn::kThreadId), QString::fromStdString(moduleRecord.threadIdText));

        rowItem->setIcon(toModuleColumnIndex(ModuleColumn::kPath), resolveProcessIcon(moduleRecord.modulePath, 16));

        // Save core data required for right-click actions.
        rowItem->setData(toModuleColumnIndex(ModuleColumn::kPath), Qt::UserRole, QString::fromStdString(moduleRecord.modulePath));
        rowItem->setData(
            toModuleColumnIndex(ModuleColumn::kPath),
            Qt::UserRole + 1,
            QVariant::fromValue<qulonglong>(moduleRecord.moduleBaseAddress));
        rowItem->setData(toModuleColumnIndex(ModuleColumn::kPath), Qt::UserRole + 2, QVariant::fromValue(moduleRecord.representativeThreadId));

        // Color based on signature trust status: green for trusted, red for untrusted, gray for Pending/unknown.
        if (moduleRecord.signatureTrusted)
        {
            rowItem->setForeground(toModuleColumnIndex(ModuleColumn::kSignature), signatureTrustedColor());
        }
        else if (moduleRecord.signatureState == "Pending" || moduleRecord.signatureState == "Unknown")
        {
            rowItem->setForeground(toModuleColumnIndex(ModuleColumn::kSignature), statusSecondaryColor());
        }
        else
        {
            rowItem->setForeground(toModuleColumnIndex(ModuleColumn::kSignature), signatureUntrustedColor());
        }

        moduleTable_->addTopLevelItem(rowItem);
    }

    moduleTable_->sortItems(toModuleColumnIndex(ModuleColumn::kPath), Qt::AscendingOrder);
}

void ProcessDetailWindow::updateModuleStatusLabel(const QString& statusText, const bool refreshing)
{
    if (moduleStatusLabel_ == nullptr)
    {
        return;
    }

    moduleStatusLabel_->setText(statusText);

    // Status label update log: output text and refresh status.
    KLogEvent moduleStatusEvent;
    dbg << moduleStatusEvent
        << "[ProcessDetailWindow] updateModuleStatusLabel: refreshing="
        << (refreshing ? "true" : "false")
        << ", statusText="
        << statusText.toStdString()
        << eol;

    if (refreshing)
    {
        moduleStatusLabel_->setStyleSheet(buildStateLabelStyle(ksword_theme::primaryBlueColor, 700));
    }
    else
    {
        moduleStatusLabel_->setStyleSheet(buildStateLabelStyle(statusIdleColor(), 600));
    }
}

void ProcessDetailWindow::showModuleContextMenu(const QPoint& localPosition)
{
    // Right-click menu entry log: record click position.
    KLogEvent moduleContextMenuEvent;
    dbg << moduleContextMenuEvent
        << "[ProcessDetailWindow] showModuleContextMenu: x="
        << localPosition.x()
        << ", y="
        << localPosition.y()
        << eol;

    QTreeWidgetItem* clickedItem = moduleTable_->itemAt(localPosition);
    if (clickedItem == nullptr)
    {
        return;
    }
    moduleTable_->setCurrentItem(clickedItem);

    QMenu contextMenu(this);
    contextMenu.setStyleSheet(QStringLiteral(
        "QMenu{"
        "  background:%1;"
        "  color:%2;"
        "  border:1px solid %3;"
        "}"
        "QMenu::item:selected{"
        "  background:%4;"
        "  color:%5;"
        "}"
        "QMenu::separator{"
        "  height:1px;"
        "  background:%3;"
        "  margin:4px 8px;"
        "}")
        .arg(ksword_theme::surfaceColorHex())
        .arg(ksword_theme::textPrimaryColorHex())
        .arg(ksword_theme::borderColorHex())
        .arg(ksword_theme::accentHex(ksword_theme::AccentRole::kBlue))
        .arg(ksword_theme::onAccentHex()));

    QAction* copyCellAction = contextMenu.addAction(QIcon(":/Icon/process_copy_cell.svg"), "复制单元格");
    QAction* copyRowAction = contextMenu.addAction(QIcon(":/Icon/process_copy_row.svg"), "复制行");
    contextMenu.addSeparator();
    QAction* gotoModuleAction = contextMenu.addAction(QIcon(":/Icon/process_details.svg"), "查看模块详情");
    QAction* openFolderAction = contextMenu.addAction(QIcon(":/Icon/process_open_folder.svg"), "打开文件夹");
    QAction* unloadAction = contextMenu.addAction(QIcon(":/Icon/process_terminate.svg"), "卸载");
    QAction* suspendThreadAction = contextMenu.addAction(QIcon(":/Icon/process_suspend.svg"), "挂起线程");
    QAction* resumeThreadAction = contextMenu.addAction(QIcon(":/Icon/process_resume.svg"), "恢复线程");
    QAction* terminateThreadAction = contextMenu.addAction(QIcon(":/Icon/process_terminate.svg"), "结束线程");

    QAction* selectedAction = contextMenu.exec(moduleTable_->viewport()->mapToGlobal(localPosition));
    if (selectedAction == nullptr)
    {
        return;
    }

    if (selectedAction == copyCellAction) { copyCurrentModuleCell(); return; }
    if (selectedAction == copyRowAction) { copyCurrentModuleRow(); return; }
    if (selectedAction == gotoModuleAction) { showCurrentModuleDetailDialog(); return; }
    if (selectedAction == openFolderAction) { openCurrentModuleFolder(); return; }
    if (selectedAction == unloadAction) { unloadCurrentModule(); return; }
    if (selectedAction == suspendThreadAction) { suspendCurrentModuleThread(); return; }
    if (selectedAction == resumeThreadAction) { resumeCurrentModuleThread(); return; }
    if (selectedAction == terminateThreadAction) { terminateCurrentModuleThread(); return; }
}

void ProcessDetailWindow::copyCurrentModuleCell()
{
    QTreeWidgetItem* currentItem = moduleTable_->currentItem();
    if (currentItem == nullptr)
    {
        return;
    }

    const int kCurrentColumn = moduleTable_->currentColumn();
    if (kCurrentColumn < 0)
    {
        return;
    }
    QApplication::clipboard()->setText(currentItem->text(kCurrentColumn));
    KLogEvent copyModuleCellEvent;
    dbg << copyModuleCellEvent
        << "[ProcessDetailWindow] copyCurrentModuleCell: column="
        << kCurrentColumn
        << eol;
}

void ProcessDetailWindow::copyCurrentModuleRow()
{
    QTreeWidgetItem* currentItem = moduleTable_->currentItem();
    if (currentItem == nullptr)
    {
        return;
    }

    QStringList fields;
    fields.reserve(static_cast<int>(ModuleColumn::kCount));
    for (int columnIndex = 0; columnIndex < static_cast<int>(ModuleColumn::kCount); ++columnIndex)
    {
        fields.push_back(currentItem->text(columnIndex));
    }
    QApplication::clipboard()->setText(fields.join("\t"));
    KLogEvent copyModuleRowEvent;
    dbg << copyModuleRowEvent
        << "[ProcessDetailWindow] copyCurrentModuleRow: 完成复制整行。"
        << eol;
}

void ProcessDetailWindow::showCurrentModuleDetailDialog()
{
    // showCurrentModuleDetailDialog:
    // - Map the current row of the module table back to a ProcessModuleRecord;
    // - Construct read-only detail text and insert it into the project's built-in CodeEditorWidget.
    // - Returns: void; allows the user to copy all or open the directory containing the module.
    ks::process::ProcessModuleRecord* moduleRecord = selectedModuleRecord();
    if (moduleRecord == nullptr)
    {
        return;
    }

    const QString kModulePathText = QString::fromStdString(moduleRecord->modulePath);
    const QString kDetailText = QStringList({
        QStringLiteral("进程 ID: %1").arg(baseRecord_.pid),
        QStringLiteral("进程名: %1").arg(QString::fromStdString(baseRecord_.processName)),
        QStringLiteral("模块路径: %1").arg(kModulePathText),
        QStringLiteral("模块基址: %1").arg(formatHexText(moduleRecord->moduleBaseAddress)),
        QStringLiteral("模块大小: %1").arg(formatModuleSizeText(moduleRecord->moduleSizeBytes)),
        QStringLiteral("入口点 RVA: %1").arg(formatHexText(moduleRecord->entryPointRva)),
        QStringLiteral("签名状态: %1").arg(QString::fromStdString(moduleRecord->signatureState)),
        QStringLiteral("签名可信: %1").arg(moduleRecord->signatureTrusted ? QStringLiteral("true") : QStringLiteral("false")),
        QStringLiteral("运行状态: %1").arg(QString::fromStdString(moduleRecord->runningState)),
        QStringLiteral("代表线程 ID: %1").arg(moduleRecord->representativeThreadId),
        QStringLiteral("线程 ID 文本: %1").arg(QString::fromStdString(moduleRecord->threadIdText))
    }).join(QChar('\n'));

    QDialog detailDialog(this);
    detailDialog.setWindowTitle(QStringLiteral("模块详情 - %1").arg(QFileInfo(kModulePathText).fileName()));
    detailDialog.resize(760, 520);
    detailDialog.setStyleSheet(QStringLiteral(
        "QDialog{background:%1;color:%2;}"
        "QPushButton{background:%3;color:%2;border:1px solid %4;border-radius:4px;padding:5px 10px;}"
        "QPushButton:hover{background:%5;}")
        .arg(ksword_theme::surfaceHex())
        .arg(ksword_theme::textPrimaryHex())
        .arg(ksword_theme::surfaceAltColorHex())
        .arg(ksword_theme::borderHex())
        .arg(ksword_theme::kPrimaryBlueHex));

    QVBoxLayout* dialogLayout = new QVBoxLayout(&detailDialog);
    dialogLayout->setContentsMargins(10, 10, 10, 10);
    dialogLayout->setSpacing(8);

    QLabel* summaryLabel = new QLabel(
        QStringLiteral("模块基址 %1 | 大小 %2 | 签名 %3")
            .arg(formatHexText(moduleRecord->moduleBaseAddress))
            .arg(formatModuleSizeText(moduleRecord->moduleSizeBytes))
            .arg(QString::fromStdString(moduleRecord->signatureState)),
        &detailDialog);
    summaryLabel->setWordWrap(true);
    dialogLayout->addWidget(summaryLabel);

    CodeEditorWidget* detailEditor = new CodeEditorWidget(&detailDialog);
    detailEditor->setReadOnly(true);
    detailEditor->setLocalizedText(kDetailText);
    dialogLayout->addWidget(detailEditor, 1);

    QHBoxLayout* buttonLayout = new QHBoxLayout();
    buttonLayout->addStretch(1);

    QPushButton* copyButton = new QPushButton(QIcon(":/Icon/process_copy_row.svg"), QStringLiteral("复制全部"), &detailDialog);
    copyButton->setToolTip(QStringLiteral("复制当前模块详情文本"));
    buttonLayout->addWidget(copyButton);

    QPushButton* openFolderButton = new QPushButton(QIcon(":/Icon/process_open_folder.svg"), QStringLiteral("打开目录"), &detailDialog);
    openFolderButton->setToolTip(QStringLiteral("打开当前模块所在文件夹"));
    buttonLayout->addWidget(openFolderButton);

    QPushButton* closeButton = new QPushButton(QStringLiteral("关闭"), &detailDialog);
    closeButton->setToolTip(QStringLiteral("关闭模块详情窗口"));
    buttonLayout->addWidget(closeButton);
    dialogLayout->addLayout(buttonLayout);

    connect(copyButton, &QPushButton::clicked, &detailDialog, [detailEditor]()
    {
        QApplication::clipboard()->setText(detailEditor->text());
    });
    connect(openFolderButton, &QPushButton::clicked, &detailDialog, [kModulePathText]()
    {
        std::string detailTextLocal;
        ks::process::openFolderByPath(kModulePathText.toStdString(), &detailTextLocal);
    });
    connect(closeButton, &QPushButton::clicked, &detailDialog, &QDialog::accept);

    KLogEvent moduleDetailEvent;
    info << moduleDetailEvent
        << "[ProcessDetailWindow] showCurrentModuleDetailDialog: path="
        << moduleRecord->modulePath
        << ", base="
        << formatHexText(moduleRecord->moduleBaseAddress).toStdString()
        << eol;

    detailDialog.exec();
}

void ProcessDetailWindow::openCurrentModuleFolder()
{
    ks::process::ProcessModuleRecord* moduleRecord = selectedModuleRecord();
    if (moduleRecord == nullptr)
    {
        return;
    }

    std::string detailText;
    const bool kActionOk = ks::process::openFolderByPath(moduleRecord->modulePath, &detailText);
    KLogEvent openModuleFolderEvent;
    info << openModuleFolderEvent
        << "[ProcessDetailWindow] openCurrentModuleFolder: path="
        << moduleRecord->modulePath
        << ", actionOk="
        << (kActionOk ? "true" : "false")
        << eol;
    showActionResultMessage("打开模块所在目录", kActionOk, detailText, openModuleFolderEvent);
}

void ProcessDetailWindow::unloadCurrentModule()
{
    ks::process::ProcessModuleRecord* moduleRecord = selectedModuleRecord();
    if (moduleRecord == nullptr)
    {
        return;
    }

    std::string detailText;
    const bool kActionOk = ks::process::unloadModuleByBaseAddressIfIdentityMatches(
        baseRecord_.pid,
        baseRecord_.creationTime100ns,
        moduleRecord->moduleBaseAddress,
        &detailText);
    KLogEvent unloadModuleEvent;
    info << unloadModuleEvent
        << "[ProcessDetailWindow] unloadCurrentModule: base="
        << formatHexText(moduleRecord->moduleBaseAddress).toStdString()
        << ", actionOk="
        << (kActionOk ? "true" : "false")
        << eol;
    showActionResultMessage("卸载模块", kActionOk, detailText, unloadModuleEvent);
    if (kActionOk)
    {
        requestAsyncModuleRefresh(true);
    }
}

void ProcessDetailWindow::suspendCurrentModuleThread()
{
    ks::process::ProcessModuleRecord* moduleRecord = selectedModuleRecord();
    if (moduleRecord == nullptr)
    {
        return;
    }
    // Suspend thread action: Reuse the same actionEvent across the entire action chain to avoid generating discrete GUIDs.
    KLogEvent actionEvent;
    if (moduleRecord->representativeThreadId == 0)
    {
        const std::string kErrorDetailText = "当前模块行没有可用 ThreadID。";
        warn << actionEvent
            << "[ProcessDetailWindow] suspendCurrentModuleThread: 缺少 ThreadID。"
            << eol;
        showActionResultMessage("挂起线程", false, kErrorDetailText, actionEvent);
        return;
    }

    std::string detailText;
    const bool kActionOk = ks::process::suspendThreadIfProcessAndThreadIdentityMatches(
        moduleRecord->representativeThreadId,
        baseRecord_.pid,
        baseRecord_.creationTime100ns,
        moduleRecord->representativeThreadCreationTime100ns,
        &detailText);
    (kActionOk ? info : err) << actionEvent
        << "[ProcessDetailWindow] suspendCurrentModuleThread: tid="
        << moduleRecord->representativeThreadId
        << ", actionOk="
        << (kActionOk ? "true" : "false")
        << eol;
    showActionResultMessage("挂起线程", kActionOk, detailText, actionEvent);
}

void ProcessDetailWindow::resumeCurrentModuleThread()
{
    ks::process::ProcessModuleRecord* moduleRecord = selectedModuleRecord();
    if (moduleRecord == nullptr)
    {
        return;
    }
    // Restores thread actions: the same action chain must uniformly reuse actionEvent to avoid discrete GUIDs.
    KLogEvent actionEvent;
    if (moduleRecord->representativeThreadId == 0)
    {
        const std::string kErrorDetailText = "当前模块行没有可用 ThreadID。";
        warn << actionEvent
            << "[ProcessDetailWindow] resumeCurrentModuleThread: 缺少 ThreadID。"
            << eol;
        showActionResultMessage("恢复线程", false, kErrorDetailText, actionEvent);
        return;
    }

    std::string detailText;
    const bool kActionOk = ks::process::resumeThreadIfProcessAndThreadIdentityMatches(
        moduleRecord->representativeThreadId,
        baseRecord_.pid,
        baseRecord_.creationTime100ns,
        moduleRecord->representativeThreadCreationTime100ns,
        &detailText);
    (kActionOk ? info : err) << actionEvent
        << "[ProcessDetailWindow] resumeCurrentModuleThread: tid="
        << moduleRecord->representativeThreadId
        << ", actionOk="
        << (kActionOk ? "true" : "false")
        << eol;
    showActionResultMessage("恢复线程", kActionOk, detailText, actionEvent);
}

void ProcessDetailWindow::terminateCurrentModuleThread()
{
    ks::process::ProcessModuleRecord* moduleRecord = selectedModuleRecord();
    if (moduleRecord == nullptr)
    {
        return;
    }
    // Thread termination action: reuse the same actionEvent across the entire action chain to avoid discrete GUIDs.
    KLogEvent actionEvent;
    if (moduleRecord->representativeThreadId == 0)
    {
        const std::string kErrorDetailText = "当前模块行没有可用 ThreadID。";
        warn << actionEvent
            << "[ProcessDetailWindow] terminateCurrentModuleThread: 缺少 ThreadID。"
            << eol;
        showActionResultMessage("结束线程", false, kErrorDetailText, actionEvent);
        return;
    }

    std::string detailText;
    const bool kActionOk = ks::process::terminateThreadIfProcessAndThreadIdentityMatches(
        moduleRecord->representativeThreadId,
        baseRecord_.pid,
        baseRecord_.creationTime100ns,
        moduleRecord->representativeThreadCreationTime100ns,
        &detailText);
    (kActionOk ? info : err) << actionEvent
        << "[ProcessDetailWindow] terminateCurrentModuleThread: tid="
        << moduleRecord->representativeThreadId
        << ", actionOk="
        << (kActionOk ? "true" : "false")
        << eol;
    showActionResultMessage("结束线程", kActionOk, detailText, actionEvent);
    if (kActionOk)
    {
        requestAsyncModuleRefresh(true);
    }
}

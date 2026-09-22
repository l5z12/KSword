#include "StartupDock.Internal.h"
#include "../online_scan/SandboxUploadActions.h"
#include "../framework/PrivilegeElevationPrompt.h"

#include <QMetaObject>

using namespace startup_dock_detail;

namespace
{
    QString startupToggleActionText(const bool enabled)
    {
        return enabled
            ? startupText("startup.menu.enable", QStringLiteral("启用"))
            : startupText("startup.menu.disable", QStringLiteral("禁用"));
    }

    QString startupToggleImpactText(
        const ks::startup::StartupActionKind actionKind,
        const bool enabled)
    {
        switch (actionKind)
        {
        case ks::startup::StartupActionKind::kRegistryRunValue:
            return enabled
                ? startupText(
                    "startup.dialog.toggle.impact.registry.enable",
                    QStringLiteral("将已停放的 Run 注册表值恢复到原位置；若原位置已被占用，不会覆盖现有值。"))
                : startupText(
                    "startup.dialog.toggle.impact.registry.disable",
                    QStringLiteral("将 Run 注册表值移入 KSword 的可恢复备份；原值数据会保留，便于重新启用。"));
        case ks::startup::StartupActionKind::kRegistryTree:
            return startupText(
                "startup.dialog.toggle.impact.registry_tree",
                QStringLiteral("永久删除精确定位的注册表子树；此操作不会创建可恢复备份。"));
        case ks::startup::StartupActionKind::kStartupFolderFile:
            return enabled
                ? startupText(
                    "startup.dialog.toggle.impact.startup_folder.enable",
                    QStringLiteral("将启动文件从 KSword 专用停放位置移回“启动”文件夹；若目标路径已存在，不会覆盖现有文件。"))
                : startupText(
                    "startup.dialog.toggle.impact.startup_folder.disable",
                    QStringLiteral("将启动文件移到 KSword 专用停放位置；文件内容会保留，之后可以重新启用。"));
        case ks::startup::StartupActionKind::kScheduledTask:
            return enabled
                ? startupText(
                    "startup.dialog.toggle.impact.task.enable",
                    QStringLiteral("重新启用计划任务，并保留其现有触发器与操作配置。"))
                : startupText(
                    "startup.dialog.toggle.impact.task.disable",
                    QStringLiteral("禁用计划任务，但保留任务定义、触发器与操作配置，之后可以重新启用。"));
        case ks::startup::StartupActionKind::kScmStartType:
            return enabled
                ? startupText(
                    "startup.dialog.toggle.impact.scm.enable",
                    QStringLiteral("把服务设置为自动启动，或把驱动设置为系统启动；不会立即启动当前服务或驱动。"))
                : startupText(
                    "startup.dialog.toggle.impact.scm.disable",
                    QStringLiteral("把服务控制管理器启动类型设为“已禁用”；当前正在运行的实例不会被停止。"));
        case ks::startup::StartupActionKind::kWmiEntryRemoval:
            return startupText(
                "startup.dialog.toggle.impact.wmi.disable",
                QStringLiteral("永久删除精确匹配的 WMI 永久事件对象；此操作不会创建可恢复备份。"));
        case ks::startup::StartupActionKind::kNone:
        default:
            return enabled
                ? startupText(
                    "startup.dialog.toggle.impact.generic.enable",
                    QStringLiteral("后端将使用已保存的结构化定位信息恢复该启动项。"))
                : startupText(
                    "startup.dialog.toggle.impact.generic.disable",
                    QStringLiteral("后端将保留恢复信息并以可逆方式禁用该启动项。"));
        }
    }

    QString startupToggleRecoveryText(const ks::startup::StartupActionKind actionKind)
    {
        switch (actionKind)
        {
        case ks::startup::StartupActionKind::kRegistryRunValue:
        case ks::startup::StartupActionKind::kStartupFolderFile:
        case ks::startup::StartupActionKind::kScheduledTask:
            return startupText(
                "startup.dialog.toggle.recovery.reversible",
                QStringLiteral("此操作保留恢复信息或原始对象，可通过右键菜单尝试改回原状态。"));
        case ks::startup::StartupActionKind::kScmStartType:
            return startupText(
                "startup.dialog.toggle.recovery.scm",
                QStringLiteral("重新启用会使用默认的自动/系统启动类型，不保证恢复修改前的精确启动类型。"));
        case ks::startup::StartupActionKind::kRegistryTree:
        case ks::startup::StartupActionKind::kWmiEntryRemoval:
            return startupText(
                "startup.dialog.toggle.recovery.irreversible",
                QStringLiteral("此操作不可由 KSword 恢复；继续前请自行确认已有可用备份。"));
        case ks::startup::StartupActionKind::kNone:
        default:
            return startupText(
                "startup.dialog.toggle.recovery.generic",
                QStringLiteral("该修改可能不可恢复，请在继续前确认影响和备份。"));
        }
    }

    QString startupRiskLevelText(const ks::startup::StartupRiskLevel riskLevel)
    {
        switch (riskLevel)
        {
        case ks::startup::StartupRiskLevel::kNormal:
            return startupText("startup.risk_level.normal", QStringLiteral("普通"));
        case ks::startup::StartupRiskLevel::kCritical:
            return startupText("startup.risk_level.critical", QStringLiteral("严重"));
        case ks::startup::StartupRiskLevel::kElevated:
        default:
            return startupText("startup.risk_level.elevated", QStringLiteral("较高"));
        }
    }

    QString startupActionStatusText(const ks::startup::StartupActionStatus status)
    {
        switch (status)
        {
        case ks::startup::StartupActionStatus::kSuccess:
            return startupText("startup.dialog.toggle.status.success", QStringLiteral("成功"));
        case ks::startup::StartupActionStatus::kNoChange:
            return startupText("startup.dialog.toggle.status.no_change", QStringLiteral("状态未变化"));
        case ks::startup::StartupActionStatus::kInvalidEntry:
            return startupText("startup.dialog.toggle.status.invalid_entry", QStringLiteral("条目无效"));
        case ks::startup::StartupActionStatus::kNotSupported:
            return startupText("startup.dialog.toggle.status.not_supported", QStringLiteral("来源类型不受支持"));
        case ks::startup::StartupActionStatus::kConflict:
            return startupText("startup.dialog.toggle.status.conflict", QStringLiteral("目标位置存在冲突"));
        case ks::startup::StartupActionStatus::kNotFound:
            return startupText("startup.dialog.toggle.status.not_found", QStringLiteral("来源或备份不存在"));
        case ks::startup::StartupActionStatus::kAccessDenied:
            return startupText("startup.dialog.toggle.status.access_denied", QStringLiteral("权限不足"));
        case ks::startup::StartupActionStatus::kWriteFailed:
            return startupText("startup.dialog.toggle.status.write_failed", QStringLiteral("写入失败"));
        case ks::startup::StartupActionStatus::kVerificationFailed:
            return startupText("startup.dialog.toggle.status.verification_failed", QStringLiteral("操作后验证失败"));
        case ks::startup::StartupActionStatus::kRollbackFailed:
            return startupText("startup.dialog.toggle.status.rollback_failed", QStringLiteral("回滚失败"));
        case ks::startup::StartupActionStatus::kProcessFailed:
            return startupText("startup.dialog.toggle.status.process_failed", QStringLiteral("系统命令执行失败"));
        default:
            return startupText("startup.dialog.toggle.status.unknown", QStringLiteral("未知错误"));
        }
    }

    QString startupActionFailureText(const ks::startup::ActionResult& actionResult)
    {
        const QString kBackendMessageText = QString::fromUtf8(
            actionResult.messageText.c_str(),
            static_cast<qsizetype>(actionResult.messageText.size())).trimmed();
        const QString kMessageText = kBackendMessageText.isEmpty()
            ? kBackendMessageText
            : ks::i18n::sourceText(kBackendMessageText);
        QString detailText = startupText(
            "startup.dialog.toggle.failed.details",
            QStringLiteral("状态：%1\n详细信息：%2"))
            .arg(startupActionStatusText(actionResult.status))
            .arg(kMessageText.isEmpty()
                ? startupText(
                    "startup.dialog.toggle.failed.no_details",
                    QStringLiteral("后端未提供附加错误信息。"))
                : kMessageText);

        if (actionResult.errorCode != ERROR_SUCCESS)
        {
            detailText += QStringLiteral("\n");
            detailText += startupText(
                "startup.dialog.toggle.failed.win32",
                QStringLiteral("Win32 错误：%1"))
                .arg(winErrorText(actionResult.errorCode));
        }

        if (actionResult.rollbackAttempted)
        {
            detailText += QStringLiteral("\n");
            detailText += actionResult.rollbackSucceeded
                ? startupText(
                    "startup.dialog.toggle.rollback.succeeded",
                    QStringLiteral("安全回滚：已成功恢复操作前状态。"))
                : startupText(
                    "startup.dialog.toggle.rollback.failed",
                    QStringLiteral("安全回滚：失败，请在刷新后核对启动项和备份状态。"));
        }
        return detailText;
    }

    bool isStartupPrivilegeFailure(const ks::startup::ActionResult& actionResult)
    {
        return actionResult.status == ks::startup::StartupActionStatus::kAccessDenied
            || actionResult.errorCode == ERROR_ACCESS_DENIED
            || actionResult.errorCode == ERROR_PRIVILEGE_NOT_HELD
            || actionResult.errorCode == ERROR_ELEVATION_REQUIRED;
    }

    QString startupTsvField(QString fieldText)
    {
        // Replace TSV row/column delimiters with visible control characters to ensure each startup item consistently occupies a single line.
        fieldText.replace(QChar('\t'), QStringLiteral("␉"));
        fieldText.replace(QChar('\r'), QStringLiteral("␍"));
        fieldText.replace(QChar('\n'), QStringLiteral("␊"));
        return fieldText;
    }

    QString startupEntryTsvRow(const StartupDock::StartupEntry& entry)
    {
        QStringList fieldList{
            entry.itemNameText,
            entry.publisherText,
            entry.imagePathText,
            entry.commandText,
            entry.locationText,
            ks::i18n::sourceText(entry.userText),
            buildStatusText(entry.backendEntry),
            ks::i18n::sourceText(entry.sourceTypeText),
            startupLocalizedDetailText(entry.detailText)
        };
        for (QString& fieldText : fieldList)
        {
            fieldText = startupTsvField(fieldText);
        }
        return fieldList.join(QChar('\t'));
    }

}

void StartupDock::initializeConnections()
{
    connect(refreshButton_, &QPushButton::clicked, this, [this]()
        {
            requestAsyncRefresh(true);
        });
    connect(exportButton_, &QPushButton::clicked, this, [this]()
        {
            exportCurrentView();
        });
    connect(copyButton_, &QPushButton::clicked, this, [this]()
        {
            copySelectedRow(currentCategory(), currentCategoryTable());
        });
    connect(filterEdit_, &QLineEdit::textChanged, this, [this](const QString&)
        {
            applyFilterAndRefresh();
        });
    connect(hideMicrosoftCheck_, &QCheckBox::toggled, this, [this](const bool)
        {
            applyFilterAndRefresh();
        });
    connect(hideEmptyPathCheck_, &QCheckBox::toggled, this, [this](const bool)
        {
            applyFilterAndRefresh();
        });

    const auto kBindTableContextMenu =
        [this](const StartupCategory category, QTableWidget* tableWidget)
        {
            if (tableWidget == nullptr)
            {
                return;
            }
            connect(tableWidget, &QWidget::customContextMenuRequested, this, [this, category, tableWidget](const QPoint& localPos)
                {
                    showEntryContextMenu(category, tableWidget, localPos);
                });
            connect(tableWidget, &QTableWidget::cellDoubleClicked, this, [this, category, tableWidget](const int row, const int /*column*/)
                {
                    if (row < 0)
                    {
                        return;
                    }
                    openSelectedFileLocation(category, tableWidget);
                });
        };

    kBindTableContextMenu(StartupCategory::kAll, allTable_);
    kBindTableContextMenu(StartupCategory::kLogon, logonTable_);
    kBindTableContextMenu(StartupCategory::kServices, servicesTable_);
    kBindTableContextMenu(StartupCategory::kDrivers, driversTable_);
    kBindTableContextMenu(StartupCategory::kTasks, tasksTable_);
    kBindTableContextMenu(StartupCategory::kImageHijack, imageHijackTable_);
    kBindTableContextMenu(StartupCategory::kWmi, wmiTable_);
    kBindTableContextMenu(StartupCategory::kHidden, hiddenTable_);

    if (registryTree_ != nullptr)
    {
        connect(registryTree_, &QWidget::customContextMenuRequested, this, [this](const QPoint& localPos)
            {
                showRegistryContextMenu(localPos);
            });
        connect(registryTree_, &QTreeWidget::itemDoubleClicked, this, [this](QTreeWidgetItem* treeItem, int)
            {
                if (treeItem == nullptr)
                {
                    return;
                }

                const StartupTreeNodeKind kNodeKind = static_cast<StartupTreeNodeKind>(
                    treeItem->data(0, kStartupTreeNodeKindRole).toInt());
                if (kNodeKind == StartupTreeNodeKind::kEntry)
                {
                    openSelectedFileLocation(StartupCategory::kRegistry, nullptr);
                }
                else if (kNodeKind == StartupTreeNodeKind::kGroup
                    || kNodeKind == StartupTreeNodeKind::kPlaceholder)
                {
                    openSelectedRegistryLocation(StartupCategory::kRegistry, nullptr);
                }
            });
    }
}

void StartupDock::refreshAllStartupEntries()
{
    requestAsyncRefresh(true);
}

void StartupDock::showEntryContextMenu(
    const StartupCategory category,
    QTableWidget* tableWidget,
    const QPoint& localPos)
{
    if (tableWidget == nullptr)
    {
        return;
    }

    QTableWidgetItem* clickedItem = tableWidget->itemAt(localPos);
    if (clickedItem == nullptr)
    {
        return;
    }
    QItemSelectionModel* const kSelectionModel = tableWidget->selectionModel();
    const QModelIndex kClickedIndex = tableWidget->indexFromItem(clickedItem);
    if (kSelectionModel != nullptr && kClickedIndex.isValid())
    {
        if (!kSelectionModel->isRowSelected(kClickedIndex.row(), QModelIndex()))
        {
            kSelectionModel->select(
                kClickedIndex,
                QItemSelectionModel::ClearAndSelect | QItemSelectionModel::Rows);
        }
        kSelectionModel->setCurrentIndex(kClickedIndex, QItemSelectionModel::NoUpdate);
    }

    const int kEntryIndex = findEntryIndexByTableRow(category, clickedItem->row());
    if (kEntryIndex < 0 || kEntryIndex >= static_cast<int>(entryList_.size()))
    {
        return;
    }

    const StartupEntry kEntry = entryList_[static_cast<std::size_t>(kEntryIndex)];
    std::vector<StartupEntry> selectedEntryList;
    if (kSelectionModel != nullptr)
    {
        const QModelIndexList kSelectedRowIndexList = kSelectionModel->selectedRows();
        selectedEntryList.reserve(static_cast<std::size_t>(kSelectedRowIndexList.size()));
        for (const QModelIndex& selectedRowIndex : kSelectedRowIndexList)
        {
            const int kSelectedEntryIndex = findEntryIndexByTableRow(
                category,
                selectedRowIndex.row());
            if (kSelectedEntryIndex >= 0
                && kSelectedEntryIndex < static_cast<int>(entryList_.size()))
            {
                selectedEntryList.push_back(
                    entryList_[static_cast<std::size_t>(kSelectedEntryIndex)]);
            }
        }
    }
    if (selectedEntryList.empty())
    {
        selectedEntryList.push_back(kEntry);
    }

    QMenu contextMenu(this);
    // Explicitly fill the menu background to avoid a black background caused by inheriting a transparent style in light mode.
    contextMenu.setStyleSheet(ksword_theme::contextMenuStyle());
    QAction* detailAction = contextMenu.addAction(
        createBlueIcon(":/Icon/process_details.svg"),
        startupText("startup.menu.entry_details", QStringLiteral("查看启动项详细信息")));
    QAction* copyAction = contextMenu.addAction(
        createBlueIcon(":/Icon/log_copy.svg"),
        startupText("startup.menu.copy_row", QStringLiteral("复制整行")));
    QAction* openFileAction = contextMenu.addAction(
        createBlueIcon(":/Icon/process_open_folder.svg"),
        startupText("startup.menu.open_file", QStringLiteral("打开文件位置")));
    QAction* filePropertiesAction = contextMenu.addAction(
        createBlueIcon(":/Icon/process_details.svg"),
        startupText("startup.menu.file_properties", QStringLiteral("转到文件属性")));
    QAction* openRegistryAction = contextMenu.addAction(
        createBlueIcon(":/Icon/file_find.svg"),
        startupText("startup.menu.open_registry", QStringLiteral("打开注册表位置")));
    QAction* gotoServiceAction = contextMenu.addAction(
        createBlueIcon(":/Icon/process_list.svg"),
        startupText("startup.menu.goto_service", QStringLiteral("转到服务管理")));
    QAction* uploadVirusTotalAction = ks::online_scan::addVirusTotalSandboxMenu(
        &contextMenu,
        this,
        [kEntry]() -> ks::online_scan::SandboxUploadTarget
        {
            // Input: Startup item cache entry.
            // Processing: Pass image path or command line to the unified path extractor.
            // Returns: Upload path and source description.
            ks::online_scan::SandboxUploadTarget uploadTarget;
            uploadTarget.filePath = kEntry.imagePathText;
            uploadTarget.sourceText = startupText(
                "startup.source.autostart",
                QStringLiteral("自启动项 %1"))
                .arg(kEntry.itemNameText);
            return uploadTarget;
        });
    contextMenu.addSeparator();
    const bool kTargetEnabled = !kEntry.enabled;
    const bool kCanApplyTargetStateToSelection = std::all_of(
        selectedEntryList.cbegin(),
        selectedEntryList.cend(),
        [kTargetEnabled](const StartupEntry& selectedEntry)
        {
            return selectedEntry.enabled == kTargetEnabled
                || (kTargetEnabled
                    ? selectedEntry.backendEntry.canEnable
                    : selectedEntry.backendEntry.canDisable);
        });
    const bool kCanDeleteSelection = std::all_of(
        selectedEntryList.cbegin(),
        selectedEntryList.cend(),
        [](const StartupEntry& selectedEntry)
        {
            return selectedEntry.canDelete && selectedEntry.backendEntry.canDelete;
        });
    QAction* toggleAction = contextMenu.addAction(
        createBlueIcon(kTargetEnabled ? ":/Icon/process_start.svg" : ":/Icon/process_pause.svg"),
        startupToggleActionText(kTargetEnabled));
    QAction* deleteAction = contextMenu.addAction(
        createBlueIcon(":/Icon/log_clear.svg"),
        startupText("startup.menu.delete", QStringLiteral("删除项")));
    openFileAction->setEnabled(kEntry.canOpenFileLocation);
    filePropertiesAction->setEnabled(kEntry.canOpenFileLocation);
    if (uploadVirusTotalAction != nullptr)
    {
        uploadVirusTotalAction->setEnabled(kEntry.canOpenFileLocation && !kEntry.imagePathText.trimmed().isEmpty());
    }
    openRegistryAction->setEnabled(kEntry.canOpenRegistryLocation);
    gotoServiceAction->setEnabled(
        kEntry.category == StartupCategory::kServices);
    toggleAction->setEnabled(
        kCanApplyTargetStateToSelection
        && !startupActionInProgress_.load());
    deleteAction->setEnabled(
        kCanDeleteSelection
        && !startupActionInProgress_.load());

    QAction* selectedAction = contextMenu.exec(tableWidget->viewport()->mapToGlobal(localPos));
    if (selectedAction == detailAction)
    {
        showSelectedEntryDetails(category, tableWidget);
    }
    else if (selectedAction == copyAction)
    {
        copySelectedRow(category, tableWidget);
    }
    else if (selectedAction == openFileAction)
    {
        openSelectedFileLocation(category, tableWidget);
    }
    else if (selectedAction == filePropertiesAction)
    {
        openSelectedFileProperties(category, tableWidget);
    }
    else if (selectedAction == openRegistryAction)
    {
        openSelectedRegistryLocation(category, tableWidget);
    }
    else if (selectedAction == gotoServiceAction)
    {
        QString serviceNameText;
        if (kEntry.uniqueIdText.startsWith(QStringLiteral("SERVICE|"), Qt::CaseInsensitive))
        {
            serviceNameText = kEntry.uniqueIdText.mid(QStringLiteral("SERVICE|").size()).trimmed();
        }
        if (serviceNameText.isEmpty())
        {
            const int kLastSlashIndex = kEntry.locationText.lastIndexOf('\\');
            serviceNameText = (kLastSlashIndex >= 0)
                ? kEntry.locationText.mid(kLastSlashIndex + 1).trimmed()
                : kEntry.itemNameText.trimmed();
        }

        QWidget* mainWindowWidget = window();
        if (mainWindowWidget != nullptr && !serviceNameText.isEmpty())
        {
            QMetaObject::invokeMethod(
                mainWindowWidget,
                "focusServiceDockByName",
                Qt::QueuedConnection,
                Q_ARG(QString, serviceNameText));
        }
    }
    else if (selectedAction == uploadVirusTotalAction)
    {
        return;
    }
    else if (selectedAction == toggleAction)
    {
        setStartupEntriesEnabled(std::move(selectedEntryList), kTargetEnabled);
    }
    else if (selectedAction == deleteAction)
    {
        deleteStartupEntries(std::move(selectedEntryList));
    }
}

void StartupDock::showRegistryContextMenu(const QPoint& localPos)
{
    if (registryTree_ == nullptr)
    {
        return;
    }

    QTreeWidgetItem* treeItem = registryTree_->itemAt(localPos);
    if (treeItem == nullptr)
    {
        return;
    }

    registryTree_->setCurrentItem(treeItem);

    const StartupTreeNodeKind kNodeKind = static_cast<StartupTreeNodeKind>(
        treeItem->data(0, kStartupTreeNodeKindRole).toInt());
    const int kEntryIndex = findEntryIndexByRegistryTreeItem(treeItem);
    const QString kLocationText = treeItem->data(0, kStartupTreeLocationRole).toString().trimmed();

    QMenu contextMenu(this);
    // Explicitly fill the menu background to avoid a black background caused by inheriting a transparent style in light mode.
    contextMenu.setStyleSheet(ksword_theme::contextMenuStyle());
    QAction* detailAction = contextMenu.addAction(
        createBlueIcon(":/Icon/process_details.svg"),
        startupText("startup.menu.entry_details", QStringLiteral("查看启动项详细信息")));
    QAction* copyAction = contextMenu.addAction(
        createBlueIcon(":/Icon/log_copy.svg"),
        startupText("startup.menu.copy", QStringLiteral("复制")));
    QAction* openFileAction = contextMenu.addAction(
        createBlueIcon(":/Icon/process_open_folder.svg"),
        startupText("startup.menu.open_file", QStringLiteral("打开文件位置")));
    QAction* filePropertiesAction = contextMenu.addAction(
        createBlueIcon(":/Icon/process_details.svg"),
        startupText("startup.menu.file_properties", QStringLiteral("转到文件属性")));
    QAction* openRegistryAction = contextMenu.addAction(
        createBlueIcon(":/Icon/file_find.svg"),
        startupText("startup.menu.open_registry", QStringLiteral("打开注册表位置")));
    const bool kHasRegistryEntry =
        kEntryIndex >= 0 && kEntryIndex < static_cast<int>(entryList_.size());
    const StartupEntry kRegistryEntry = kHasRegistryEntry
        ? entryList_[static_cast<std::size_t>(kEntryIndex)]
        : StartupEntry{};
    QAction* uploadVirusTotalAction = ks::online_scan::addVirusTotalSandboxMenu(
        &contextMenu,
        this,
        [kHasRegistryEntry, kRegistryEntry]() -> ks::online_scan::SandboxUploadTarget
        {
            // Input: Current leaf entry in the advanced registry tree.
            // Processing: Only leaf entries extract upload files from imagePathText.
            // Returns: Upload path and source description.
            ks::online_scan::SandboxUploadTarget uploadTarget;
            if (!kHasRegistryEntry)
            {
                uploadTarget.errorText = startupText(
                    "startup.upload.error.invalid_node",
                    QStringLiteral("当前注册表节点不是可上传的启动项。"));
                return uploadTarget;
            }
            uploadTarget.filePath = kRegistryEntry.imagePathText;
            uploadTarget.sourceText = startupText(
                "startup.source.autostart_registry",
                QStringLiteral("自启动注册表项 %1"))
                .arg(kRegistryEntry.itemNameText);
            return uploadTarget;
        });
    contextMenu.addSeparator();
    const bool kTargetEnabled = !kHasRegistryEntry || !kRegistryEntry.enabled;
    QAction* toggleAction = contextMenu.addAction(
        createBlueIcon(kTargetEnabled ? ":/Icon/process_start.svg" : ":/Icon/process_pause.svg"),
        startupToggleActionText(kTargetEnabled));
    QAction* deleteAction = contextMenu.addAction(
        createBlueIcon(":/Icon/log_clear.svg"),
        startupText("startup.menu.delete", QStringLiteral("删除项")));

    if (kNodeKind == StartupTreeNodeKind::kGroup
        || kNodeKind == StartupTreeNodeKind::kPlaceholder)
    {
        openFileAction->setEnabled(false);
        filePropertiesAction->setEnabled(false);
        if (uploadVirusTotalAction != nullptr)
        {
            uploadVirusTotalAction->setEnabled(false);
        }
        openRegistryAction->setEnabled(!kLocationText.isEmpty());
        toggleAction->setEnabled(false);
        deleteAction->setEnabled(false);
    }
    else if (kEntryIndex >= 0 && kEntryIndex < static_cast<int>(entryList_.size()))
    {
        const StartupEntry& entry = kRegistryEntry;
        openFileAction->setEnabled(entry.canOpenFileLocation);
        filePropertiesAction->setEnabled(entry.canOpenFileLocation);
        if (uploadVirusTotalAction != nullptr)
        {
            uploadVirusTotalAction->setEnabled(entry.canOpenFileLocation && !entry.imagePathText.trimmed().isEmpty());
        }
        openRegistryAction->setEnabled(entry.canOpenRegistryLocation);
        const bool kToggleSupported = kTargetEnabled
            ? entry.backendEntry.canEnable
            : entry.backendEntry.canDisable;
        toggleAction->setEnabled(
            kToggleSupported
            && !startupActionInProgress_.load());
        deleteAction->setEnabled(
            entry.canDelete
            && !startupActionInProgress_.load());
    }
    else
    {
        openFileAction->setEnabled(false);
        filePropertiesAction->setEnabled(false);
        if (uploadVirusTotalAction != nullptr)
        {
            uploadVirusTotalAction->setEnabled(false);
        }
        openRegistryAction->setEnabled(false);
        toggleAction->setEnabled(false);
        deleteAction->setEnabled(false);
    }

    QAction* selectedAction = contextMenu.exec(registryTree_->viewport()->mapToGlobal(localPos));
    if (selectedAction == detailAction)
    {
        showSelectedEntryDetails(StartupCategory::kRegistry, nullptr);
    }
    else if (selectedAction == copyAction)
    {
        copySelectedRow(StartupCategory::kRegistry, nullptr);
    }
    else if (selectedAction == openFileAction)
    {
        openSelectedFileLocation(StartupCategory::kRegistry, nullptr);
    }
    else if (selectedAction == filePropertiesAction)
    {
        openSelectedFileProperties(StartupCategory::kRegistry, nullptr);
    }
    else if (selectedAction == openRegistryAction)
    {
        openSelectedRegistryLocation(StartupCategory::kRegistry, nullptr);
    }
    else if (selectedAction == uploadVirusTotalAction)
    {
        return;
    }
    else if (selectedAction == toggleAction && kHasRegistryEntry)
    {
        setStartupEntryEnabled(kRegistryEntry, kTargetEnabled);
    }
    else if (selectedAction == deleteAction && kHasRegistryEntry)
    {
        deleteStartupEntry(kRegistryEntry);
    }
}

void StartupDock::openSelectedFileLocation(const StartupCategory category, QTableWidget* tableWidget)
{
    int entryIndex = -1;
    if (category == StartupCategory::kRegistry)
    {
        entryIndex = findEntryIndexByRegistryTreeItem(
            registryTree_ != nullptr ? registryTree_->currentItem() : nullptr);
    }
    else if (tableWidget != nullptr && tableWidget->currentRow() >= 0)
    {
        entryIndex = findEntryIndexByTableRow(category, tableWidget->currentRow());
    }
    if (entryIndex < 0 || entryIndex >= static_cast<int>(entryList_.size()))
    {
        return;
    }

    const StartupEntry& entry = entryList_[static_cast<std::size_t>(entryIndex)];
    if (!entry.canOpenFileLocation || entry.imagePathText.trimmed().isEmpty())
    {
        QMessageBox::information(
            this,
            startupText("startup.dialog.title", QStringLiteral("启动项")),
            startupText(
                "startup.dialog.open_file.no_path",
                QStringLiteral("该条目没有可打开的文件路径。")));
        return;
    }

    QProcess::startDetached(
        QStringLiteral("explorer.exe"),
        { QStringLiteral("/select,%1").arg(QDir::toNativeSeparators(entry.imagePathText)) });
}

void StartupDock::openSelectedRegistryLocation(const StartupCategory category, QTableWidget* tableWidget)
{
    QString locationText;
    if (category == StartupCategory::kRegistry)
    {
        QTreeWidgetItem* currentItem = (registryTree_ != nullptr) ? registryTree_->currentItem() : nullptr;
        if (currentItem == nullptr)
        {
            return;
        }

        const StartupTreeNodeKind kNodeKind = static_cast<StartupTreeNodeKind>(
            currentItem->data(0, kStartupTreeNodeKindRole).toInt());
        if (kNodeKind == StartupTreeNodeKind::kGroup || kNodeKind == StartupTreeNodeKind::kPlaceholder)
        {
            locationText = currentItem->data(0, kStartupTreeLocationRole).toString().trimmed();
        }
        else
        {
            const int kEntryIndex = findEntryIndexByRegistryTreeItem(currentItem);
            if (kEntryIndex >= 0 && kEntryIndex < static_cast<int>(entryList_.size()))
            {
                locationText = entryList_[static_cast<std::size_t>(kEntryIndex)].locationText;
            }
        }
    }
    else if (tableWidget != nullptr && tableWidget->currentRow() >= 0)
    {
        const int kEntryIndex = findEntryIndexByTableRow(category, tableWidget->currentRow());
        if (kEntryIndex >= 0 && kEntryIndex < static_cast<int>(entryList_.size()))
        {
            locationText = entryList_[static_cast<std::size_t>(kEntryIndex)].locationText;
        }
    }
    if (locationText.trimmed().isEmpty())
    {
        QMessageBox::information(
            this,
            startupText("startup.dialog.title", QStringLiteral("启动项")),
            startupText(
                "startup.dialog.open_registry.no_path",
                QStringLiteral("该条目没有可打开的注册表位置。")));
        return;
    }

    QApplication::clipboard()->setText(locationText);
    QProcess::startDetached(QStringLiteral("regedit.exe"), {});
    QMessageBox::information(
        this,
        startupText("startup.dialog.title", QStringLiteral("启动项")),
        startupText(
            "startup.dialog.open_registry.success",
            QStringLiteral("已复制注册表路径到剪贴板，并尝试打开 regedit。")));
}

void StartupDock::copySelectedRow(const StartupCategory category, QTableWidget* tableWidget)
{
    if (category == StartupCategory::kRegistry)
    {
        QTreeWidgetItem* currentItem = (registryTree_ != nullptr) ? registryTree_->currentItem() : nullptr;
        if (currentItem == nullptr)
        {
            return;
        }

        const StartupTreeNodeKind kNodeKind = static_cast<StartupTreeNodeKind>(
            currentItem->data(0, kStartupTreeNodeKindRole).toInt());
        if (kNodeKind == StartupTreeNodeKind::kGroup || kNodeKind == StartupTreeNodeKind::kPlaceholder)
        {
            QApplication::clipboard()->setText(currentItem->data(0, kStartupTreeLocationRole).toString());
            return;
        }

        const int kEntryIndex = findEntryIndexByRegistryTreeItem(currentItem);
        if (kEntryIndex < 0 || kEntryIndex >= static_cast<int>(entryList_.size()))
        {
            return;
        }

        const StartupEntry& entry = entryList_[static_cast<std::size_t>(kEntryIndex)];
        QApplication::clipboard()->setText(startupEntryTsvRow(entry));
        return;
    }

    if (tableWidget == nullptr || tableWidget->currentRow() < 0)
    {
        return;
    }

    const int kEntryIndex = findEntryIndexByTableRow(category, tableWidget->currentRow());
    if (kEntryIndex < 0 || kEntryIndex >= static_cast<int>(entryList_.size()))
    {
        return;
    }

    const StartupEntry& entry = entryList_[static_cast<std::size_t>(kEntryIndex)];
    QApplication::clipboard()->setText(startupEntryTsvRow(entry));
}

void StartupDock::exportCurrentView()
{
    const QString kOutputPath = QFileDialog::getSaveFileName(
        this,
        startupText("startup.dialog.export.title", QStringLiteral("导出启动项")),
        QStringLiteral("StartupEntries.txt"),
        QStringLiteral("Text Files (*.txt);;All Files (*.*)"));
    if (kOutputPath.trimmed().isEmpty())
    {
        return;
    }

    QFile outputFile(kOutputPath);
    if (!outputFile.open(QIODevice::WriteOnly | QIODevice::Text))
    {
        QMessageBox::warning(
            this,
            startupText("startup.dialog.title", QStringLiteral("启动项")),
            startupText("startup.dialog.export.failed", QStringLiteral("导出失败：%1"))
                .arg(outputFile.errorString()));
        return;
    }

    QTextStream outputStream(&outputFile);
    outputStream.setEncoding(QStringConverter::Utf8);
    outputStream << startupTableHeaders().join(QChar('\t')) << '\n';
    if (currentCategory() == StartupCategory::kRegistry)
    {
        if (registryTree_ == nullptr)
        {
            return;
        }

        for (int rootIndex = 0; rootIndex < registryTree_->topLevelItemCount(); ++rootIndex)
        {
            QTreeWidgetItem* groupItem = registryTree_->topLevelItem(rootIndex);
            if (groupItem == nullptr)
            {
                continue;
            }

            for (int childIndex = 0; childIndex < groupItem->childCount(); ++childIndex)
            {
                QTreeWidgetItem* childItem = groupItem->child(childIndex);
                const int kEntryIndex = findEntryIndexByRegistryTreeItem(childItem);
                if (kEntryIndex < 0 || kEntryIndex >= static_cast<int>(entryList_.size()))
                {
                    continue;
                }

                const StartupEntry& entry = entryList_[static_cast<std::size_t>(kEntryIndex)];
                outputStream << startupEntryTsvRow(entry) << '\n';
            }
        }
    }
    else
    {
        QTableWidget* tableWidget = currentCategoryTable();
        if (tableWidget == nullptr)
        {
            return;
        }

        for (int rowIndex = 0; rowIndex < tableWidget->rowCount(); ++rowIndex)
        {
            const int kEntryIndex = findEntryIndexByTableRow(currentCategory(), rowIndex);
            if (kEntryIndex < 0 || kEntryIndex >= static_cast<int>(entryList_.size()))
            {
                continue;
            }

            const StartupEntry& entry = entryList_[static_cast<std::size_t>(kEntryIndex)];
            outputStream << startupEntryTsvRow(entry) << '\n';
        }
    }
}

void StartupDock::applyFilterAndRefresh()
{
    rebuildAllTables();
}

void StartupDock::setStartupEntryEnabled(StartupEntry entry, const bool enabled)
{
    const QString kActionText = startupToggleActionText(enabled);
    const QString kOperationTitle = startupText(
        "startup.dialog.toggle.operation.title",
        QStringLiteral("%1启动项"))
        .arg(kActionText);

    const bool kActionSupported = enabled
        ? entry.backendEntry.canEnable
        : entry.backendEntry.canDisable;
    if (!kActionSupported)
    {
        QMessageBox::information(
            this,
            kOperationTitle,
            startupText(
                "startup.dialog.toggle.unsupported",
                QStringLiteral("后端未允许对该条目执行“%1”。请刷新后查看最新状态。"))
                .arg(kActionText));
        return;
    }

    if (enabled)
    {
        const QString kLocationText = entry.locationText.trimmed().isEmpty()
            ? startupText("startup.value.empty", QStringLiteral("<空>"))
            : entry.locationText;
        const QMessageBox::StandardButton kConfirmButton = QMessageBox::warning(
            this,
            startupText(
                "startup.dialog.toggle.confirm.title",
                QStringLiteral("确认%1"))
                .arg(kOperationTitle),
            startupText(
                "startup.dialog.toggle.confirm.message",
                QStringLiteral("%1\n\n条目：%2\n来源：%3\n目标状态：%4\n风险等级：%5\n风险提示：%6\n\n%7\n是否继续？"))
                .arg(startupToggleImpactText(entry.backendEntry.actionKind, enabled))
                .arg(entry.itemNameText)
                .arg(kLocationText)
                .arg(buildStatusText(enabled))
                .arg(startupRiskLevelText(entry.backendEntry.riskLevel))
                .arg(startupRiskReasonText(entry.backendEntry))
                .arg(startupToggleRecoveryText(entry.backendEntry.actionKind)),
            QMessageBox::Yes | QMessageBox::No,
            QMessageBox::No);
        if (kConfirmButton != QMessageBox::Yes)
        {
            return;
        }
    }

    bool expectedIdle = false;
    if (!startupActionInProgress_.compare_exchange_strong(expectedIdle, true))
    {
        QMessageBox::information(
            this,
            kOperationTitle,
            startupText(
                "startup.dialog.toggle.busy",
                QStringLiteral("已有一个启动项启停操作正在执行，请等待其完成后重试。")));
        return;
    }

    const ks::startup::StartupEntry kBackendEntry = entry.backendEntry;
    const QString kItemNameText = entry.itemNameText;
    const QString kSourceTypeText = entry.sourceTypeText;
    const QString kEntryLocationText = entry.locationText;
    if (actionThread_ != nullptr && actionThread_->joinable())
    {
        actionThread_->join();
    }
    actionThread_ = std::make_unique<std::thread>(
        [this,
         kBackendEntry,
         enabled,
         kActionText,
         kOperationTitle,
         kItemNameText,
         kSourceTypeText,
         kEntryLocationText]()
    {
        const ks::startup::ActionResult kActionResult =
            ks::startup::setStartupEntryEnabled(kBackendEntry, enabled);
        if (destroying_.load())
        {
            return;
        }

        const bool kCallbackQueued = QMetaObject::invokeMethod(
            this,
            [this,
             kActionResult,
             enabled,
             kActionText,
             kOperationTitle,
             kItemNameText,
             kSourceTypeText,
             kEntryLocationText]()
            {
                if (destroying_.load())
                {
                    return;
                }

                startupActionInProgress_.store(false);
                refreshAllStartupEntries();
                if (!kActionResult.success)
                {
                    const QString kFailureText = startupActionFailureText(kActionResult);
                    bool privilegePromptHandled = false;
                    if (isStartupPrivilegeFailure(kActionResult))
                    {
                        if (kActionResult.errorCode != ERROR_SUCCESS)
                        {
                            privilegePromptHandled = ks::ui::promptForPrivilegeFailure(
                                this,
                                kOperationTitle,
                                static_cast<unsigned long>(kActionResult.errorCode));
                        }
                        if (!privilegePromptHandled)
                        {
                            privilegePromptHandled = ks::ui::promptForPrivilegeFailure(
                                this,
                                kOperationTitle,
                                kFailureText);
                        }
                    }
                    if (!privilegePromptHandled)
                    {
                        QMessageBox::warning(
                            this,
                            startupText(
                                "startup.dialog.toggle.failed.title",
                                QStringLiteral("%1失败"))
                                .arg(kOperationTitle),
                            kFailureText);
                    }
                    return;
                }

                KLogEvent actionEvent;
                info << actionEvent
                    << startupText(
                        "startup.log.toggle.succeeded",
                        QStringLiteral("[StartupDock] 启动项修改成功, action=%1, changed=%2, targetEnabled=%3, type=%4, name=%5, location=%6"))
                           .arg(kActionText)
                           .arg(kActionResult.changed ? QStringLiteral("true") : QStringLiteral("false"))
                           .arg(enabled ? QStringLiteral("true") : QStringLiteral("false"))
                           .arg(kSourceTypeText)
                           .arg(kItemNameText)
                           .arg(kEntryLocationText)
                           .toStdString()
                    << eol;
            },
            Qt::QueuedConnection);
        if (!kCallbackQueued)
        {
            startupActionInProgress_.store(false);
        }
    });
}

void StartupDock::deleteStartupEntry(StartupEntry entry)
{
    const QString kOperationTitle = startupText(
        "startup.dialog.delete.operation.title",
        QStringLiteral("删除启动项"));
    if (!entry.canDelete || !entry.backendEntry.canDelete)
    {
        QMessageBox::information(
            this,
            kOperationTitle,
            startupText("startup.dialog.delete.unsupported", QStringLiteral("该条目当前不支持删除。")));
        return;
    }

    const QMessageBox::StandardButton kConfirmButton = QMessageBox::warning(
        this,
        startupText(
            "startup.dialog.delete.confirm.irreversible.title",
            QStringLiteral("永久删除启动项")),
        startupText(
            "startup.dialog.delete.confirm.irreversible.message",
            QStringLiteral("即将永久删除以下启动项及其来源记录：\n\n%1\n来源：%2\n风险等级：%3\n风险提示：%4\n\n此操作不可通过 KSword 恢复。若只是暂时停止启动，请取消并使用“禁用”。\n\n确定仍要永久删除吗？"))
            .arg(entry.itemNameText)
            .arg(entry.locationText)
            .arg(startupRiskLevelText(entry.backendEntry.riskLevel))
            .arg(startupRiskReasonText(entry.backendEntry)),
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);
    if (kConfirmButton != QMessageBox::Yes)
    {
        return;
    }

    bool expectedIdle = false;
    if (!startupActionInProgress_.compare_exchange_strong(expectedIdle, true))
    {
        QMessageBox::information(
            this,
            kOperationTitle,
            startupText(
                "startup.dialog.operation.busy",
                QStringLiteral("已有一个启动项修改操作正在执行，请等待其完成后重试。")));
        return;
    }

    const ks::startup::StartupEntry kBackendEntry = entry.backendEntry;
    const QString kItemNameText = entry.itemNameText;
    const QString kSourceTypeText = entry.sourceTypeText;
    const QString kEntryLocationText = entry.locationText;
    if (actionThread_ != nullptr && actionThread_->joinable())
    {
        actionThread_->join();
    }
    actionThread_ = std::make_unique<std::thread>(
        [this,
         kBackendEntry,
         kOperationTitle,
         kItemNameText,
         kSourceTypeText,
         kEntryLocationText]()
    {
        const ks::startup::ActionResult kActionResult =
            ks::startup::deleteStartupEntry(kBackendEntry);
        if (destroying_.load())
        {
            return;
        }

        const bool kCallbackQueued = QMetaObject::invokeMethod(
            this,
            [this,
             kActionResult,
             kOperationTitle,
             kItemNameText,
             kSourceTypeText,
             kEntryLocationText]()
            {
                if (destroying_.load())
                {
                    return;
                }

                startupActionInProgress_.store(false);
                refreshAllStartupEntries();
                if (!kActionResult.success)
                {
                    const QString kFailureText = startupActionFailureText(kActionResult);
                    bool privilegePromptHandled = false;
                    if (isStartupPrivilegeFailure(kActionResult))
                    {
                        if (kActionResult.errorCode != ERROR_SUCCESS)
                        {
                            privilegePromptHandled = ks::ui::promptForPrivilegeFailure(
                                this,
                                kOperationTitle,
                                static_cast<unsigned long>(kActionResult.errorCode));
                        }
                        if (!privilegePromptHandled)
                        {
                            privilegePromptHandled = ks::ui::promptForPrivilegeFailure(
                                this,
                                kOperationTitle,
                                kFailureText);
                        }
                    }
                    if (!privilegePromptHandled)
                    {
                        QMessageBox::warning(
                            this,
                            kOperationTitle,
                            startupText(
                                "startup.dialog.delete.failed",
                                QStringLiteral("删除失败：%1"))
                                .arg(kFailureText));
                    }
                    return;
                }

                KLogEvent deleteEvent;
                info << deleteEvent
                    << startupText(
                        "startup.log.delete.succeeded",
                        QStringLiteral("[StartupDock] 删除启动项成功, type="))
                           .toStdString()
                    << kSourceTypeText.toStdString()
                    << ", name="
                    << kItemNameText.toStdString()
                    << ", location="
                    << kEntryLocationText.toStdString()
                    << ", changed="
                    << (kActionResult.changed ? "true" : "false")
                    << eol;
            },
            Qt::QueuedConnection);
        if (!kCallbackQueued)
        {
            startupActionInProgress_.store(false);
        }
    });
}

void StartupDock::setStartupEntriesEnabled(
    std::vector<StartupEntry> entryList,
    const bool enabled)
{
    if (entryList.size() <= 1)
    {
        if (!entryList.empty())
        {
            setStartupEntryEnabled(std::move(entryList.front()), enabled);
        }
        return;
    }

    const QString kActionText = startupToggleActionText(enabled);
    const QString kOperationTitle = startupText(
        "startup.dialog.toggle.operation.title",
        QStringLiteral("%1启动项"))
        .arg(kActionText);
    std::vector<StartupEntry> actionableEntryList;
    actionableEntryList.reserve(entryList.size());
    for (const StartupEntry& entry : entryList)
    {
        if (entry.enabled == enabled)
        {
            continue;
        }

        const bool kActionSupported = enabled
            ? entry.backendEntry.canEnable
            : entry.backendEntry.canDisable;
        if (!kActionSupported)
        {
            QMessageBox::information(
                this,
                kOperationTitle,
                startupText(
                    "startup.dialog.toggle.unsupported",
                    QStringLiteral("后端未允许对该条目执行“%1”。请刷新后查看最新状态。"))
                    .arg(kActionText));
            return;
        }
        actionableEntryList.push_back(entry);
    }
    if (actionableEntryList.empty())
    {
        return;
    }

    if (enabled)
    {
        const QMessageBox::StandardButton kConfirmButton = QMessageBox::warning(
            this,
            startupText(
                "startup.dialog.toggle.confirm.title",
                QStringLiteral("确认%1"))
                .arg(kOperationTitle),
            startupText(
                "startup.dialog.toggle.confirm.batch.message",
                QStringLiteral("即将%1 %2 个启动项。操作会逐项执行；失败项不会中断其余项目。\n\n是否继续？"))
                .arg(kActionText)
                .arg(actionableEntryList.size()),
            QMessageBox::Yes | QMessageBox::No,
            QMessageBox::No);
        if (kConfirmButton != QMessageBox::Yes)
        {
            return;
        }
    }

    bool expectedIdle = false;
    if (!startupActionInProgress_.compare_exchange_strong(expectedIdle, true))
    {
        QMessageBox::information(
            this,
            kOperationTitle,
            startupText(
                "startup.dialog.toggle.busy",
                QStringLiteral("已有一个启动项启停操作正在执行，请等待其完成后重试。")));
        return;
    }

    if (actionThread_ != nullptr && actionThread_->joinable())
    {
        actionThread_->join();
    }
    actionThread_ = std::make_unique<std::thread>(
        [this, actionableEntryList, enabled, kActionText, kOperationTitle]()
    {
        std::vector<std::pair<StartupEntry, ks::startup::ActionResult>> actionResultList;
        actionResultList.reserve(actionableEntryList.size());
        for (const StartupEntry& entry : actionableEntryList)
        {
            actionResultList.emplace_back(
                entry,
                ks::startup::setStartupEntryEnabled(entry.backendEntry, enabled));
        }
        if (destroying_.load())
        {
            return;
        }

        const bool kCallbackQueued = QMetaObject::invokeMethod(
            this,
            [this, actionResultList, enabled, kActionText, kOperationTitle]()
            {
                if (destroying_.load())
                {
                    return;
                }

                startupActionInProgress_.store(false);
                refreshAllStartupEntries();
                QStringList failureTextList;
                bool privilegePromptHandled = false;
                for (const auto& actionResultEntry : actionResultList)
                {
                    const StartupEntry& entry = actionResultEntry.first;
                    const ks::startup::ActionResult& actionResult = actionResultEntry.second;
                    if (!actionResult.success)
                    {
                        const QString kFailureText = startupActionFailureText(actionResult);
                        if (!privilegePromptHandled && isStartupPrivilegeFailure(actionResult))
                        {
                            privilegePromptHandled = actionResult.errorCode != ERROR_SUCCESS
                                ? ks::ui::promptForPrivilegeFailure(
                                    this,
                                    kOperationTitle,
                                    static_cast<unsigned long>(actionResult.errorCode))
                                : ks::ui::promptForPrivilegeFailure(
                                    this,
                                    kOperationTitle,
                                    kFailureText);
                        }
                        failureTextList.push_back(
                            QStringLiteral("%1：%2").arg(entry.itemNameText, kFailureText));
                        continue;
                    }

                    KLogEvent actionEvent;
                    info << actionEvent
                        << startupText(
                            "startup.log.toggle.succeeded",
                            QStringLiteral("[StartupDock] 启动项修改成功, action=%1, changed=%2, targetEnabled=%3, type=%4, name=%5, location=%6"))
                               .arg(kActionText)
                               .arg(actionResult.changed ? QStringLiteral("true") : QStringLiteral("false"))
                               .arg(enabled ? QStringLiteral("true") : QStringLiteral("false"))
                               .arg(entry.sourceTypeText)
                               .arg(entry.itemNameText)
                               .arg(entry.locationText)
                               .toStdString()
                        << eol;
                }

                if (!failureTextList.isEmpty() && !privilegePromptHandled)
                {
                    QMessageBox::warning(
                        this,
                        startupText(
                            "startup.dialog.toggle.failed.title",
                            QStringLiteral("%1失败"))
                            .arg(kOperationTitle),
                        startupText(
                            "startup.dialog.batch.failed",
                            QStringLiteral("%1 个条目未能执行%2：\n\n%3"))
                            .arg(failureTextList.size())
                            .arg(kActionText)
                            .arg(failureTextList.join(QStringLiteral("\n\n"))));
                }
            },
            Qt::QueuedConnection);
        if (!kCallbackQueued)
        {
            startupActionInProgress_.store(false);
        }
    });
}

void StartupDock::deleteStartupEntries(std::vector<StartupEntry> entryList)
{
    if (entryList.size() <= 1)
    {
        if (!entryList.empty())
        {
            deleteStartupEntry(std::move(entryList.front()));
        }
        return;
    }

    const QString kOperationTitle = startupText(
        "startup.dialog.delete.operation.title",
        QStringLiteral("删除启动项"));
    for (const StartupEntry& entry : entryList)
    {
        if (!entry.canDelete || !entry.backendEntry.canDelete)
        {
            QMessageBox::information(
                this,
                kOperationTitle,
                startupText("startup.dialog.delete.unsupported", QStringLiteral("该条目当前不支持删除。")));
            return;
        }
    }

    const QMessageBox::StandardButton kConfirmButton = QMessageBox::warning(
        this,
        startupText(
            "startup.dialog.delete.confirm.irreversible.title",
            QStringLiteral("永久删除启动项")),
        startupText(
            "startup.dialog.delete.confirm.batch.message",
            QStringLiteral("即将永久删除 %1 个启动项及其来源记录。此操作不可通过 KSword 恢复。\n\n确定仍要永久删除吗？"))
            .arg(entryList.size()),
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);
    if (kConfirmButton != QMessageBox::Yes)
    {
        return;
    }

    bool expectedIdle = false;
    if (!startupActionInProgress_.compare_exchange_strong(expectedIdle, true))
    {
        QMessageBox::information(
            this,
            kOperationTitle,
            startupText(
                "startup.dialog.operation.busy",
                QStringLiteral("已有一个启动项修改操作正在执行，请等待其完成后重试。")));
        return;
    }

    if (actionThread_ != nullptr && actionThread_->joinable())
    {
        actionThread_->join();
    }
    actionThread_ = std::make_unique<std::thread>(
        [this, entryList, kOperationTitle]()
    {
        std::vector<std::pair<StartupEntry, ks::startup::ActionResult>> actionResultList;
        actionResultList.reserve(entryList.size());
        for (const StartupEntry& entry : entryList)
        {
            actionResultList.emplace_back(
                entry,
                ks::startup::deleteStartupEntry(entry.backendEntry));
        }
        if (destroying_.load())
        {
            return;
        }

        const bool kCallbackQueued = QMetaObject::invokeMethod(
            this,
            [this, actionResultList, kOperationTitle]()
            {
                if (destroying_.load())
                {
                    return;
                }

                startupActionInProgress_.store(false);
                refreshAllStartupEntries();
                QStringList failureTextList;
                bool privilegePromptHandled = false;
                for (const auto& actionResultEntry : actionResultList)
                {
                    const StartupEntry& entry = actionResultEntry.first;
                    const ks::startup::ActionResult& actionResult = actionResultEntry.second;
                    if (!actionResult.success)
                    {
                        const QString kFailureText = startupActionFailureText(actionResult);
                        if (!privilegePromptHandled && isStartupPrivilegeFailure(actionResult))
                        {
                            privilegePromptHandled = actionResult.errorCode != ERROR_SUCCESS
                                ? ks::ui::promptForPrivilegeFailure(
                                    this,
                                    kOperationTitle,
                                    static_cast<unsigned long>(actionResult.errorCode))
                                : ks::ui::promptForPrivilegeFailure(
                                    this,
                                    kOperationTitle,
                                    kFailureText);
                        }
                        failureTextList.push_back(
                            QStringLiteral("%1：%2").arg(entry.itemNameText, kFailureText));
                        continue;
                    }

                    KLogEvent deleteEvent;
                    info << deleteEvent
                        << startupText(
                            "startup.log.delete.succeeded",
                            QStringLiteral("[StartupDock] 删除启动项成功, type="))
                               .toStdString()
                        << entry.sourceTypeText.toStdString()
                        << ", name="
                        << entry.itemNameText.toStdString()
                        << ", location="
                        << entry.locationText.toStdString()
                        << ", changed="
                        << (actionResult.changed ? "true" : "false")
                        << eol;
                }

                if (!failureTextList.isEmpty() && !privilegePromptHandled)
                {
                    QMessageBox::warning(
                        this,
                        kOperationTitle,
                        startupText(
                            "startup.dialog.batch.failed",
                            QStringLiteral("%1 个条目未能执行%2：\n\n%3"))
                            .arg(failureTextList.size())
                            .arg(kOperationTitle)
                            .arg(failureTextList.join(QStringLiteral("\n\n"))));
                }
            },
            Qt::QueuedConnection);
        if (!kCallbackQueued)
        {
            startupActionInProgress_.store(false);
        }
    });
}

int StartupDock::findEntryIndexByTableRow(const StartupCategory category, const int row) const
{
    QTableWidget* tableWidget = nullptr;
    switch (category)
    {
    case StartupCategory::kAll:
        tableWidget = allTable_;
        break;
    case StartupCategory::kLogon:
        tableWidget = logonTable_;
        break;
    case StartupCategory::kServices:
        tableWidget = servicesTable_;
        break;
    case StartupCategory::kDrivers:
        tableWidget = driversTable_;
        break;
    case StartupCategory::kTasks:
        tableWidget = tasksTable_;
        break;
    case StartupCategory::kImageHijack:
        tableWidget = imageHijackTable_;
        break;
    case StartupCategory::kRegistry:
        return -1;
    case StartupCategory::kWmi:
        tableWidget = wmiTable_;
        break;
    case StartupCategory::kHidden:
        tableWidget = hiddenTable_;
        break;
    default:
        break;
    }

    if (tableWidget == nullptr || row < 0)
    {
        return -1;
    }

    QTableWidgetItem* nameItem = tableWidget->item(row, toStartupColumn(StartupColumn::kName));
    if (nameItem == nullptr)
    {
        return -1;
    }
    return nameItem->data(Qt::UserRole).toInt();
}

bool StartupDock::entryMatchesCurrentFilter(const StartupEntry& entry) const
{
    const QString kKeywordText = (filterEdit_ != nullptr) ? filterEdit_->text().trimmed() : QString();
    const bool kHideMicrosoft = (hideMicrosoftCheck_ != nullptr) && hideMicrosoftCheck_->isChecked();

    if (kHideMicrosoft)
    {
        const QString kPublisherLowerText = entry.publisherText.toLower();
        if (kPublisherLowerText.contains(QStringLiteral("microsoft"))
            || kPublisherLowerText.contains(QStringLiteral("windows")))
        {
            return false;
        }
    }

    if (kKeywordText.isEmpty())
    {
        return true;
    }

    const QString kHaystackText =
        entry.itemNameText + QLatin1Char('\n')
        + entry.publisherText + QLatin1Char('\n')
        + entry.imagePathText + QLatin1Char('\n')
        + entry.commandText + QLatin1Char('\n')
        + entry.locationText + QLatin1Char('\n')
        + entry.userText + QLatin1Char('\n')
        + ks::i18n::sourceText(entry.userText) + QLatin1Char('\n')
        + entry.sourceTypeText + QLatin1Char('\n')
        + ks::i18n::sourceText(entry.sourceTypeText) + QLatin1Char('\n')
        + buildStatusText(entry.backendEntry) + QLatin1Char('\n')
        + entry.detailText + QLatin1Char('\n')
        + startupLocalizedDetailText(entry.detailText);
    return kHaystackText.contains(kKeywordText, Qt::CaseInsensitive);
}

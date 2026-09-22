#include "StartupDock.Internal.h"

#include "../ui/CodeEditorWidget.h"

using namespace startup_dock_detail;

namespace
{
    // boolText：
    // - Purpose: Uniformly converts boolean values to Chinese 'Yes/No'.
    // - Call: Reused when assembling startup item detail text.
    QString boolText(const bool value)
    {
        return value
            ? startupText("startup.value.yes", QStringLiteral("是"))
            : startupText("startup.value.no", QStringLiteral("否"));
    }

    QString emptyValueText()
    {
        return startupText("startup.value.empty", QStringLiteral("<空>"));
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

    // buildEntryDetailText：
    // - Purpose: Expand a StartupEntry into detailed text;
    // - Invocation: Used when viewing startup entry details.
    // - Input entry: the currently selected startup entry record;
    // - Out: Returns plain text ready to be passed directly to CodeEditorWidget.
    QString buildEntryDetailText(const StartupDock::StartupEntry& entry)
    {
        QString detailText;
        detailText += startupText("startup.detail.name", QStringLiteral("名称：%1\n")).arg(entry.itemNameText);
        detailText += startupText("startup.detail.category", QStringLiteral("分类：%1\n"))
            .arg(ks::i18n::sourceText(entry.categoryText));
        detailText += startupText("startup.detail.publisher", QStringLiteral("发布者：%1\n"))
            .arg(entry.publisherText.isEmpty() ? emptyValueText() : entry.publisherText);
        detailText += startupText("startup.detail.image_path", QStringLiteral("镜像路径：%1\n"))
            .arg(entry.imagePathText.isEmpty() ? emptyValueText() : entry.imagePathText);
        detailText += startupText("startup.detail.command", QStringLiteral("命令：%1\n"))
            .arg(entry.commandText.isEmpty() ? emptyValueText() : entry.commandText);
        detailText += startupText("startup.detail.location", QStringLiteral("来源位置：%1\n"))
            .arg(entry.locationText.isEmpty() ? emptyValueText() : entry.locationText);
        detailText += startupText("startup.detail.group_location", QStringLiteral("分组位置：%1\n"))
            .arg(entry.locationGroupText.isEmpty() ? emptyValueText() : entry.locationGroupText);
        detailText += startupText("startup.detail.registry_value", QStringLiteral("注册表值名：%1\n"))
            .arg(entry.registryValueNameText.isEmpty() ? emptyValueText() : entry.registryValueNameText);
        detailText += startupText("startup.detail.user_context", QStringLiteral("用户/上下文：%1\n"))
            .arg(entry.userText.isEmpty() ? emptyValueText() : ks::i18n::sourceText(entry.userText));
        detailText += startupText("startup.detail.type", QStringLiteral("类型：%1\n"))
            .arg(entry.sourceTypeText.isEmpty() ? emptyValueText() : ks::i18n::sourceText(entry.sourceTypeText));
        detailText += startupText("startup.detail.status", QStringLiteral("状态：%1\n"))
            .arg(buildStatusText(entry.backendEntry));
        detailText += startupText("startup.detail.can_enable", QStringLiteral("可启用：%1\n"))
            .arg(boolText(entry.backendEntry.canEnable));
        detailText += startupText("startup.detail.can_disable", QStringLiteral("可禁用：%1\n"))
            .arg(boolText(entry.backendEntry.canDisable));
        const bool kActionAvailable = entry.backendEntry.canEnable
            || entry.backendEntry.canDisable
            || entry.canDelete;
        detailText += startupText("startup.detail.modification_policy", QStringLiteral("修改策略：%1\n"))
            .arg(kActionAvailable
                ? startupText("startup.value.warning_gated", QStringLiteral("警告后允许"))
                : startupText("startup.value.action_unavailable", QStringLiteral("没有可执行的来源定位器")));
        detailText += startupText("startup.detail.risk_warning", QStringLiteral("风险提示：%1\n"))
            .arg(startupRiskReasonText(entry.backendEntry));
        detailText += startupText("startup.detail.risk_level", QStringLiteral("风险等级：%1\n"))
            .arg(startupRiskLevelText(entry.backendEntry.riskLevel));
        detailText += startupText("startup.detail.description", QStringLiteral("补充说明：%1\n"))
            .arg(entry.detailText.isEmpty() ? emptyValueText() : startupLocalizedDetailText(entry.detailText));
        detailText += startupText("startup.detail.file_location", QStringLiteral("可打开文件位置：%1\n"))
            .arg(boolText(entry.canOpenFileLocation));
        detailText += startupText("startup.detail.registry_location", QStringLiteral("可打开注册表位置：%1\n"))
            .arg(boolText(entry.canOpenRegistryLocation));
        detailText += startupText("startup.detail.deletable", QStringLiteral("可删除：%1\n"))
            .arg(boolText(entry.canDelete));
        detailText += startupText("startup.detail.delete_registry_tree", QStringLiteral("删除整棵注册表子键：%1\n"))
            .arg(boolText(entry.deleteRegistryTree));
        detailText += startupText("startup.detail.unique_id", QStringLiteral("唯一标识：%1\n"))
            .arg(entry.uniqueIdText.isEmpty() ? QStringLiteral("<空>") : entry.uniqueIdText);
        return detailText;
    }

    // buildRegistryNodeDetailText：
    // - Purpose: Generate detail text for registry tree location nodes and placeholder nodes.
    // - Usage: Called when the user right-clicks to view details of a registry location node.
    // - Input treeItem: currently selected tree node.
    // - Output: Text content ready for direct display.
    QString buildRegistryNodeDetailText(const QTreeWidgetItem* treeItem)
    {
        if (treeItem == nullptr)
        {
            return startupText("startup.detail.node.empty", QStringLiteral("<空节点>"));
        }

        const StartupTreeNodeKind kNodeKind = static_cast<StartupTreeNodeKind>(
            treeItem->data(0, kStartupTreeNodeKindRole).toInt());
        const QString kKindText =
            kNodeKind == StartupTreeNodeKind::kGroup
            ? startupText("startup.detail.node.registry_group", QStringLiteral("注册表位置节点"))
            : (kNodeKind == StartupTreeNodeKind::kPlaceholder
                ? startupText("startup.detail.node.placeholder", QStringLiteral("占位节点"))
                : startupText("startup.detail.node.entry", QStringLiteral("条目节点")));

        QString detailText;
        detailText += startupText("startup.detail.node.type", QStringLiteral("节点类型：%1\n")).arg(kKindText);
        detailText += startupText("startup.detail.node.display_text", QStringLiteral("显示文本：%1\n"))
            .arg(treeItem->text(StartupDock::toStartupColumn(StartupDock::StartupColumn::kName)));
        detailText += startupText("startup.detail.node.registry_location", QStringLiteral("注册表位置：%1\n"))
            .arg(treeItem->data(0, kStartupTreeLocationRole).toString());
        detailText += startupText("startup.detail.node.detail_column", QStringLiteral("详情列：%1\n"))
            .arg(treeItem->text(StartupDock::toStartupColumn(StartupDock::StartupColumn::kDetail)));
        detailText += startupText("startup.detail.node.children_count", QStringLiteral("子节点数量：%1\n"))
            .arg(treeItem->childCount());
        return detailText;
    }

    // showStartupDetailDialog：
    // - Purpose: Unified popup for startup item / registry node detail dialog.
    // - Call: Triggered by the right-click menu action 'View Startup Item Details';
    // - Input: titleText/detailText for window title and body text.
    // - Return: None; display modally directly.
    void showStartupDetailDialog(QWidget* parentWidget, const QString& titleText, const QString& detailText)
    {
        QDialog detailDialog(parentWidget);
        detailDialog.setObjectName(QStringLiteral("StartupDockDetailDialog"));
        detailDialog.setWindowTitle(titleText);
        detailDialog.resize(860, 620);
        // Force the details dialog to use an opaque background to avoid a black background in light mode.
        detailDialog.setStyleSheet(ksword_theme::opaqueDialogStyle(detailDialog.objectName()));

        QVBoxLayout* layout = new QVBoxLayout(&detailDialog);
        CodeEditorWidget* detailEditor = new CodeEditorWidget(&detailDialog);
        detailEditor->setReadOnly(true);
        detailEditor->setLocalizedText(detailText);

        QDialogButtonBox* buttonBox = new QDialogButtonBox(QDialogButtonBox::Close, &detailDialog);
        QObject::connect(buttonBox, &QDialogButtonBox::rejected, &detailDialog, &QDialog::reject);
        QObject::connect(buttonBox, &QDialogButtonBox::accepted, &detailDialog, &QDialog::accept);

        layout->addWidget(detailEditor, 1);
        layout->addWidget(buttonBox, 0);
        detailDialog.exec();
    }

    // openFilePropertiesByPath：
    // - Purpose: Open the file properties dialog;
    // - Call: Triggered by the right-click menu action 'Go to File Properties'.
    // - Input filePathText: target file path.
    // - Output: Returns true if ShellExecute was successfully triggered.
    bool openFilePropertiesByPath(const QString& filePathText, QString* errorTextOut)
    {
        if (filePathText.trimmed().isEmpty())
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = startupText(
                    "startup.dialog.file_properties.error.empty_path",
                    QStringLiteral("文件路径为空。"));
            }
            return false;
        }

        const HINSTANCE kShellResult = ::ShellExecuteW(
            nullptr,
            L"properties",
            reinterpret_cast<LPCWSTR>(QDir::toNativeSeparators(filePathText).utf16()),
            nullptr,
            nullptr,
            SW_SHOW);
        if (reinterpret_cast<INT_PTR>(kShellResult) <= 32)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = startupText(
                    "startup.dialog.file_properties.error.failed",
                    QStringLiteral("ShellExecute(properties) 失败，返回值=%1"))
                    .arg(reinterpret_cast<INT_PTR>(kShellResult));
            }
            return false;
        }
        return true;
    }
}

void StartupDock::showSelectedEntryDetails(const StartupCategory category, QTableWidget* tableWidget)
{
    if (category == StartupCategory::kRegistry)
    {
        QTreeWidgetItem* currentItem = (registryTree_ != nullptr) ? registryTree_->currentItem() : nullptr;
        if (currentItem == nullptr)
        {
            return;
        }

        const int kEntryIndex = findEntryIndexByRegistryTreeItem(currentItem);
        if (kEntryIndex >= 0 && kEntryIndex < static_cast<int>(entryList_.size()))
        {
            const StartupEntry& entry = entryList_[static_cast<std::size_t>(kEntryIndex)];
            showStartupDetailDialog(
                this,
                startupText("startup.dialog.entry_detail.title", QStringLiteral("启动项详细信息 - %1"))
                    .arg(entry.itemNameText),
                buildEntryDetailText(entry));
        }
        else
        {
            showStartupDetailDialog(
                this,
                startupText("startup.dialog.registry_detail.title", QStringLiteral("注册表位置详细信息")),
                buildRegistryNodeDetailText(currentItem));
        }
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
    showStartupDetailDialog(
        this,
        startupText("startup.dialog.entry_detail.title", QStringLiteral("启动项详细信息 - %1"))
            .arg(entry.itemNameText),
        buildEntryDetailText(entry));
}

void StartupDock::openSelectedFileProperties(const StartupCategory category, QTableWidget* tableWidget)
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
                "startup.dialog.file_properties.no_path",
                QStringLiteral("该条目没有可查看属性的文件路径。")));
        return;
    }

    QString errorText;
    if (!openFilePropertiesByPath(entry.imagePathText, &errorText))
    {
        QMessageBox::warning(
            this,
            startupText("startup.dialog.title", QStringLiteral("启动项")),
            startupText("startup.dialog.file_properties.failed", QStringLiteral("打开文件属性失败：%1"))
                .arg(errorText));
    }
}

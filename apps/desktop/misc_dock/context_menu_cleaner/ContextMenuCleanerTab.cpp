#include "ContextMenuCleanerTab.h"
#include "../../framework/PrivilegeElevationPrompt.h"
#include "../../ui/VisibleTableWidget.h"

#include "ContextMenuCleanerTab.Internal.h"
#include "../../Theme.h"

#include <QAbstractItemView>
#include <QAction>
#include <QApplication>
#include <QClipboard>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QIcon>
#include <QItemSelectionModel>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMessageBox>
#include <QPushButton>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTabWidget>
#include <QVBoxLayout>
#include <QStringList>

#include <array>

namespace ks::misc
{

using namespace context_menu_cleaner_detail;

ContextMenuCleanerTab::ContextMenuCleanerTab(QWidget* parent)
    : QWidget(parent)
{
    initializeUi();
    refreshArea(MenuArea::kInternetExplorer);

    KLogEvent event;
    info << event << "[ContextMenuCleanerTab] 右键菜单清理页初始化完成。" << eol;
}

void ContextMenuCleanerTab::initializeUi()
{
    // Root layout: risk description above, seven categories of Shell association sub-pages below.
    rootLayout_ = new QVBoxLayout(this);
    rootLayout_->setContentsMargins(6, 6, 6, 6);
    rootLayout_->setSpacing(6);

    areaTabWidget_ = new QTabWidget(this);
    areaTabWidget_->setObjectName(QStringLiteral("ksContextMenuCleanerAreaTabs"));
    rootLayout_->addWidget(areaTabWidget_, 1);

    createAreaPage(MenuArea::kInternetExplorer);
    createAreaPage(MenuArea::kDesktop);
    createAreaPage(MenuArea::kFile);
    createAreaPage(MenuArea::kUrlBinding);
    createAreaPage(MenuArea::kOpenWith);
    createAreaPage(MenuArea::kFormatMenu);
    createAreaPage(MenuArea::kExplorerHome);

    // Tab lazy loading:
    // - URL/Format menus scan a large number of Classes subkeys; do not block the UI once during construction of the Misc page.
    // - enumerate once when the user first switches to a category; thereafter, only the refresh button triggers a re-scan.
    const std::array<MenuArea, 7> kOrderedAreas{
        MenuArea::kInternetExplorer,
        MenuArea::kDesktop,
        MenuArea::kFile,
        MenuArea::kUrlBinding,
        MenuArea::kOpenWith,
        MenuArea::kFormatMenu,
        MenuArea::kExplorerHome
    };
    connect(
        areaTabWidget_,
        &QTabWidget::currentChanged,
        this,
        [this, kOrderedAreas](const int tabIndex) {
            if (tabIndex < 0
                || tabIndex >= static_cast<int>(kOrderedAreas.size()))
            {
                return;
            }
            const MenuArea kArea = kOrderedAreas[static_cast<std::size_t>(tabIndex)];
            AreaWidgets* areaWidgets = widgetsForArea(kArea);
            if (areaWidgets != nullptr && !areaWidgets->hasLoaded)
            {
                refreshArea(kArea);
            }
        });
}

void ContextMenuCleanerTab::createAreaPage(const MenuArea area)
{
    AreaWidgets* areaWidgets = widgetsForArea(area);
    if (areaWidgets == nullptr)
    {
        return;
    }

    areaWidgets->page = new QWidget(areaTabWidget_);
    areaWidgets->layout = new QVBoxLayout(areaWidgets->page);
    areaWidgets->layout->setContentsMargins(0, 0, 0, 0);
    areaWidgets->layout->setSpacing(6);

    areaWidgets->toolbarWidget = new QWidget(areaWidgets->page);
    QHBoxLayout* toolbarLayout = new QHBoxLayout(areaWidgets->toolbarWidget);
    toolbarLayout->setContentsMargins(0, 0, 0, 0);
    toolbarLayout->setSpacing(6);
    areaWidgets->layout->addWidget(areaWidgets->toolbarWidget);

    areaWidgets->refreshButton = new QPushButton(QIcon(QStringLiteral(":/Icon/process_refresh.svg")), QStringLiteral("刷新"), areaWidgets->toolbarWidget);
    areaWidgets->refreshButton->setToolTip(QStringLiteral("重新枚举当前分类的 Shell 关联注册表项目"));
    areaWidgets->deleteButton = new QPushButton(QIcon(QStringLiteral(":/Icon/process_terminate.svg")), QStringLiteral("删除选中"), areaWidgets->toolbarWidget);
    // Backup scope varies by category; placing this on the delete button is more aligned with the actual action than a generic note at the page header.
    areaWidgets->deleteButton->setToolTip(
        area == MenuArea::kUrlBinding
            ? QStringLiteral("删除表格选中项对应的注册表子树或值。本分类删除前会自动备份，可用「恢复上次删除」还原；更改后通常需要重启 Explorer 或相关程序才会完全刷新。")
            : QStringLiteral("删除表格选中项对应的注册表子树或值。本分类不会自动备份；更改后通常需要重启 Explorer 或相关程序才会完全刷新。"));
    if (area == MenuArea::kUrlBinding)
    {
        areaWidgets->restoreButton = new QPushButton(
            QIcon(QStringLiteral(":/Icon/codeeditor_undo.svg")),
            QStringLiteral("恢复上次删除"),
            areaWidgets->toolbarWidget);
        areaWidgets->restoreButton->setToolTip(QStringLiteral("恢复上一次 URL 绑定删除前自动保存的注册表树"));
    }
    areaWidgets->copyButton = new QPushButton(QIcon(QStringLiteral(":/Icon/log_copy.svg")), QStringLiteral("复制路径"), areaWidgets->toolbarWidget);
    areaWidgets->copyButton->setToolTip(QStringLiteral("复制选中项的注册表路径"));
    areaWidgets->filterEdit = new QLineEdit(areaWidgets->toolbarWidget);
    areaWidgets->filterEdit->setClearButtonEnabled(true);
    areaWidgets->filterEdit->setPlaceholderText(QStringLiteral("筛选：名称/显示名/命令/注册表路径/CLSID"));
    areaWidgets->filterEdit->setStyleSheet(buildInputStyle());

    areaWidgets->refreshButton->setStyleSheet(ksword_theme::themedButtonStyle());
    areaWidgets->deleteButton->setStyleSheet(ksword_theme::themedButtonStyle());
    if (areaWidgets->restoreButton != nullptr)
    {
        areaWidgets->restoreButton->setStyleSheet(ksword_theme::themedButtonStyle());
    }
    areaWidgets->copyButton->setStyleSheet(ksword_theme::themedButtonStyle());

    toolbarLayout->addWidget(areaWidgets->refreshButton);
    toolbarLayout->addWidget(areaWidgets->deleteButton);
    if (areaWidgets->restoreButton != nullptr)
    {
        toolbarLayout->addWidget(areaWidgets->restoreButton);
    }
    toolbarLayout->addWidget(areaWidgets->copyButton);
    toolbarLayout->addWidget(areaWidgets->filterEdit, 1);

    areaWidgets->table = new ks::ui::VisibleTableWidget(areaWidgets->page);
    areaWidgets->table->setColumnCount(kColumnCount);
    areaWidgets->table->setHorizontalHeaderLabels(QStringList{
        QStringLiteral("名称"),
        QStringLiteral("显示名"),
        QStringLiteral("类型"),
        QStringLiteral("来源"),
        QStringLiteral("命令/处理器"),
        QStringLiteral("注册表位置"),
        QStringLiteral("状态"),
        QStringLiteral("详情") });
    areaWidgets->table->setSelectionBehavior(QAbstractItemView::SelectRows);
    areaWidgets->table->setSelectionMode(QAbstractItemView::ExtendedSelection);
    areaWidgets->table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    areaWidgets->table->setAlternatingRowColors(true);
    areaWidgets->table->setContextMenuPolicy(Qt::CustomContextMenu);
    areaWidgets->table->setHorizontalScrollMode(QAbstractItemView::ScrollPerPixel);
    areaWidgets->table->setSortingEnabled(true);
    areaWidgets->table->verticalHeader()->setVisible(false);
    areaWidgets->table->horizontalHeader()->setStyleSheet(buildHeaderStyle());
    areaWidgets->table->horizontalHeader()->setSectionResizeMode(kColumnName, QHeaderView::ResizeToContents);
    areaWidgets->table->horizontalHeader()->setSectionResizeMode(kColumnDisplayName, QHeaderView::ResizeToContents);
    areaWidgets->table->horizontalHeader()->setSectionResizeMode(kColumnKind, QHeaderView::ResizeToContents);
    areaWidgets->table->horizontalHeader()->setSectionResizeMode(kColumnSource, QHeaderView::ResizeToContents);
    areaWidgets->table->horizontalHeader()->setSectionResizeMode(kColumnCommandOrHandler, QHeaderView::Stretch);
    areaWidgets->table->horizontalHeader()->setSectionResizeMode(kColumnRegistryPath, QHeaderView::Stretch);
    areaWidgets->table->horizontalHeader()->setSectionResizeMode(kColumnStatus, QHeaderView::ResizeToContents);
    areaWidgets->table->horizontalHeader()->setSectionResizeMode(kColumnDetail, QHeaderView::Stretch);
    areaWidgets->layout->addWidget(areaWidgets->table, 1);

    areaWidgets->statusLabel = new QLabel(QStringLiteral("尚未刷新。"), areaWidgets->page);
    areaWidgets->statusLabel->setWordWrap(true);
    areaWidgets->layout->addWidget(areaWidgets->statusLabel);

    connect(areaWidgets->refreshButton, &QPushButton::clicked, this, [this, area]() {
        refreshArea(area);
    });
    connect(areaWidgets->deleteButton, &QPushButton::clicked, this, [this, area]() {
        deleteSelectedEntries(area);
    });
    if (areaWidgets->restoreButton != nullptr)
    {
        connect(areaWidgets->restoreButton, &QPushButton::clicked, this, [this]() {
            restoreLastUrlBindingBackup();
        });
    }
    connect(areaWidgets->copyButton, &QPushButton::clicked, this, [this, area]() {
        copySelectedEntries(area);
    });
    connect(areaWidgets->filterEdit, &QLineEdit::textChanged, this, [this, area](const QString&) {
        rebuildAreaTable(area);
    });
    connect(areaWidgets->table, &QTableWidget::customContextMenuRequested, this, [this, area](const QPoint& localPosition) {
        showAreaContextMenu(area, localPosition);
    });

    areaTabWidget_->addTab(areaWidgets->page, QIcon(areaIconPath(area)), areaTitle(area));
}

void ContextMenuCleanerTab::refreshArea(const MenuArea area)
{
    AreaWidgets* areaWidgets = widgetsForArea(area);
    if (areaWidgets == nullptr)
    {
        return;
    }

    const QVector<ContextMenuEntry> kNewEntries = enumerateEntriesForArea(area);
    areaWidgets->entries = kNewEntries;
    areaWidgets->hasLoaded = true;
    rebuildAreaTable(area);

    KLogEvent event;
    info << event
        << "[ContextMenuCleanerTab] 刷新分类完成, area="
        << areaTitle(area).toStdString()
        << ", count="
        << kNewEntries.size()
        << eol;
}

void ContextMenuCleanerTab::rebuildAreaTable(const MenuArea area)
{
    AreaWidgets* areaWidgets = widgetsForArea(area);
    if (areaWidgets == nullptr || areaWidgets->table == nullptr)
    {
        return;
    }

    const QString kFilterText = areaWidgets->filterEdit != nullptr
        ? areaWidgets->filterEdit->text().trimmed().toLower()
        : QString();

    areaWidgets->table->setSortingEnabled(false);
    areaWidgets->table->setRowCount(0);

    int visibleCount = 0;
    for (int entryIndex = 0; entryIndex < areaWidgets->entries.size(); ++entryIndex)
    {
        const ContextMenuEntry& entry = areaWidgets->entries.at(entryIndex);
        const QString kSearchableText = QStringList{
            entry.itemName,
            entry.displayName,
            entry.entryKind,
            entry.sourceGroup,
            entry.commandOrHandler,
            registryTargetPathText(
                entry.rootLabel,
                entry.subKeyPath,
                entry.deleteKind == DeleteKind::kRegistryValue,
                entry.valueName),
            entry.statusText,
            entry.detailText,
            entry.clsidText }.join('\n').toLower();
        if (!kFilterText.isEmpty() && !kSearchableText.contains(kFilterText))
        {
            continue;
        }

        const int kRow = visibleCount++;
        areaWidgets->table->insertRow(kRow);

        const auto kMakeItem = [entryIndex](const QString& text) -> QTableWidgetItem*
        {
            QTableWidgetItem* item = new QTableWidgetItem(text);
            item->setData(Qt::UserRole, entryIndex);
            item->setToolTip(text);
            return item;
        };

        areaWidgets->table->setItem(kRow, kColumnName, kMakeItem(entry.itemName));
        areaWidgets->table->setItem(kRow, kColumnDisplayName, kMakeItem(entry.displayName));
        areaWidgets->table->setItem(kRow, kColumnKind, kMakeItem(entry.entryKind));
        areaWidgets->table->setItem(kRow, kColumnSource, kMakeItem(entry.sourceGroup));
        areaWidgets->table->setItem(kRow, kColumnCommandOrHandler, kMakeItem(entry.commandOrHandler));
        areaWidgets->table->setItem(
            kRow,
            kColumnRegistryPath,
            kMakeItem(registryTargetPathText(
                entry.rootLabel,
                entry.subKeyPath,
                entry.deleteKind == DeleteKind::kRegistryValue,
                entry.valueName)));
        areaWidgets->table->setItem(kRow, kColumnStatus, kMakeItem(entry.statusText));
        areaWidgets->table->setItem(kRow, kColumnDetail, kMakeItem(entry.detailText));
    }

    areaWidgets->table->setSortingEnabled(true);
    if (areaWidgets->statusLabel != nullptr)
    {
        areaWidgets->statusLabel->setText(QStringLiteral("%1：共枚举 %2 项，当前显示 %3 项。")
            .arg(areaTitle(area))
            .arg(areaWidgets->entries.size())
            .arg(visibleCount));
    }
}

void ContextMenuCleanerTab::showAreaContextMenu(const MenuArea area, const QPoint& localPosition)
{
    AreaWidgets* areaWidgets = widgetsForArea(area);
    if (areaWidgets == nullptr || areaWidgets->table == nullptr)
    {
        return;
    }

    QMenu menu(areaWidgets->table);
    menu.setStyleSheet(ksword_theme::contextMenuStyle());
    QAction* copyAction = menu.addAction(QIcon(QStringLiteral(":/Icon/log_copy.svg")), QStringLiteral("复制注册表路径"));
    QAction* deleteAction = menu.addAction(QIcon(QStringLiteral(":/Icon/process_terminate.svg")), QStringLiteral("删除选中项"));

    const QVector<int> kSelectedIndexes = selectedEntryIndexes(area);
    bool hasDeleteableEntry = false;
    for (const int kEntryIndex : kSelectedIndexes)
    {
        if (kEntryIndex >= 0
            && kEntryIndex < areaWidgets->entries.size()
            && areaWidgets->entries.at(kEntryIndex).canDelete)
        {
            hasDeleteableEntry = true;
            break;
        }
    }
    copyAction->setEnabled(!kSelectedIndexes.isEmpty());
    deleteAction->setEnabled(hasDeleteableEntry);

    QAction* selectedAction = menu.exec(areaWidgets->table->viewport()->mapToGlobal(localPosition));
    if (selectedAction == copyAction)
    {
        copySelectedEntries(area);
    }
    else if (selectedAction == deleteAction)
    {
        deleteSelectedEntries(area);
    }
}

void ContextMenuCleanerTab::deleteSelectedEntries(const MenuArea area)
{
    AreaWidgets* areaWidgets = widgetsForArea(area);
    if (areaWidgets == nullptr)
    {
        return;
    }

    const QVector<int> kSelectedIndexes = selectedEntryIndexes(area);
    if (kSelectedIndexes.isEmpty())
    {
        QMessageBox::information(this, QStringLiteral("Shell 关联管理"), QStringLiteral("请先选择需要删除的注册表项目。"));
        return;
    }

    QStringList targetPaths;
    QVector<int> deleteableIndexes;
    int machineScopeTargetCount = 0;
    for (const int kEntryIndex : kSelectedIndexes)
    {
        if (kEntryIndex < 0 || kEntryIndex >= areaWidgets->entries.size())
        {
            continue;
        }
        const ContextMenuEntry& entry = areaWidgets->entries.at(kEntryIndex);
        if (!entry.canDelete
            || (area == MenuArea::kUrlBinding && !isUrlBindingDeletionAllowed(entry)))
        {
            continue;
        }
        deleteableIndexes.push_back(kEntryIndex);
        if (entry.rootKey == HKEY_LOCAL_MACHINE)
        {
            ++machineScopeTargetCount;
        }
        targetPaths.push_back(registryTargetPathText(
            entry.rootLabel,
            entry.subKeyPath,
            entry.deleteKind == DeleteKind::kRegistryValue,
            entry.valueName));
    }
    if (deleteableIndexes.isEmpty())
    {
        QMessageBox::information(
            this,
            QStringLiteral("Shell 关联管理"),
            QStringLiteral("选中项属于受保护的系统注册，当前页面不允许删除。"));
        return;
    }

    const QString kPreviewText = targetPaths.mid(0, 8).join('\n');
    const QString kMoreText = targetPaths.size() > 8
        ? QStringLiteral("\n... 另有 %1 项").arg(targetPaths.size() - 8)
        : QString();
    const QString kMachineScopeWarning = machineScopeTargetCount > 0
        ? QStringLiteral("\n\n高风险警告：其中 %1 项位于 HKLM，修改会影响所有用户，错误删除可能使协议、应用入口或系统功能失效。KSword 不限制此操作，但只应在确认目标属于第三方软件时继续；恢复 HKLM 备份需要管理员权限。")
            .arg(machineScopeTargetCount)
        : QString();
    const QString kConfirmationText = area == MenuArea::kUrlBinding
        ? QStringLiteral("将删除 %1 个 URL 绑定注册表子树。删除前会自动备份，可通过“恢复上次删除”还原。%2\n\n%3%4")
            .arg(targetPaths.size())
            .arg(kMachineScopeWarning)
            .arg(kPreviewText)
            .arg(kMoreText)
        : QStringLiteral("将删除 %1 个注册表子树或值。此操作不会自动备份，删除后通常需要重启 Explorer 或相关程序才会完全生效。\n\n%2%3")
            .arg(targetPaths.size())
            .arg(kPreviewText)
            .arg(kMoreText);
    const QMessageBox::StandardButton kConfirmButton = QMessageBox::warning(
        this,
        QStringLiteral("确认删除注册表项目"),
        kConfirmationText,
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);
    if (kConfirmButton != QMessageBox::Yes)
    {
        return;
    }

    if (area == MenuArea::kUrlBinding)
    {
        QString backupError;
        if (!createUrlBindingBackup(deleteableIndexes, &backupError))
        {
            QMessageBox::critical(
                this,
                QStringLiteral("URL 绑定备份失败"),
                QStringLiteral("删除已取消，因为无法建立可恢复备份：\n\n%1").arg(backupError));
            return;
        }
    }

    QStringList failedMessages;
    int successCount = 0;
    // privilegePromptHandled: Show the privilege restoration prompt at most once during batch deletion and suppress the final duplicate failure dialog.
    bool privilegePromptHandled = false;
    for (const int kEntryIndex : deleteableIndexes)
    {
        if (kEntryIndex < 0 || kEntryIndex >= areaWidgets->entries.size())
        {
            continue;
        }
        const ContextMenuEntry& entry = areaWidgets->entries.at(kEntryIndex);
        if (area == MenuArea::kUrlBinding && !isUrlBindingDeletionAllowed(entry))
        {
            failedMessages.push_back(QStringLiteral("%1：执行时安全校验拒绝删除")
                .arg(registryTargetPathText(
                    entry.rootLabel,
                    entry.subKeyPath,
                    entry.deleteKind == DeleteKind::kRegistryValue,
                    entry.valueName)));
            continue;
        }
        QString errorText;
        const bool kDeleteOk = entry.deleteKind == DeleteKind::kRegistryValue
            ? deleteRegistryValueWithView(
                entry.rootKey,
                entry.subKeyPath,
                entry.valueName,
                entry.viewFlag,
                entry.cleanupOpenWithMru,
                &errorText)
            : deleteRegistryTreeWithView(
                entry.rootKey,
                entry.subKeyPath,
                entry.viewFlag,
                &errorText);
        const QString kTargetPath = registryTargetPathText(
            entry.rootLabel,
            entry.subKeyPath,
            entry.deleteKind == DeleteKind::kRegistryValue,
            entry.valueName);
        if (kDeleteOk)
        {
            ++successCount;
            KLogEvent event;
            warn << event
                << "[ContextMenuCleanerTab] 删除 Shell 关联注册表项目成功, path="
                << kTargetPath.toStdString()
                << eol;
        }
        else
        {
            if (!privilegePromptHandled)
            {
                privilegePromptHandled = ks::ui::promptForPrivilegeFailure(
                    this,
                    QStringLiteral("清理 Shell 关联注册表项目"),
                    errorText);
            }
            failedMessages.push_back(QStringLiteral("%1：%2")
                .arg(kTargetPath, errorText));
            KLogEvent event;
            err << event
                << "[ContextMenuCleanerTab] 删除 Shell 关联注册表项目失败, path="
                << kTargetPath.toStdString()
                << ", error="
                << errorText.toStdString()
                << eol;
        }
    }

    refreshArea(area);

    if (failedMessages.isEmpty())
    {
        QMessageBox::information(
            this,
            QStringLiteral("Shell 关联管理"),
            QStringLiteral("已删除 %1 项。建议重启 Explorer 或相关程序后确认变化。").arg(successCount));
    }
    else
    {
        if (!privilegePromptHandled)
        {
            QMessageBox::warning(
                this,
                QStringLiteral("Shell 关联管理"),
                QStringLiteral("成功删除 %1 项，失败 %2 项：\n\n%3")
                    .arg(successCount)
                    .arg(failedMessages.size())
                    .arg(failedMessages.join('\n')));
        }
    }
}

void ContextMenuCleanerTab::copySelectedEntries(const MenuArea area) const
{
    const AreaWidgets* areaWidgets = widgetsForArea(area);
    if (areaWidgets == nullptr)
    {
        return;
    }

    const QVector<int> kSelectedIndexes = selectedEntryIndexes(area);
    if (kSelectedIndexes.isEmpty())
    {
        QMessageBox::information(const_cast<ContextMenuCleanerTab*>(this), QStringLiteral("复制注册表路径"), QStringLiteral("请先选择需要复制的行。"));
        return;
    }

    QStringList lines;
    for (const int kEntryIndex : kSelectedIndexes)
    {
        if (kEntryIndex < 0 || kEntryIndex >= areaWidgets->entries.size())
        {
            continue;
        }
        const ContextMenuEntry& entry = areaWidgets->entries.at(kEntryIndex);
        lines.push_back(registryTargetPathText(
            entry.rootLabel,
            entry.subKeyPath,
            entry.deleteKind == DeleteKind::kRegistryValue,
            entry.valueName));
    }

    if (QClipboard* clipboard = QApplication::clipboard())
    {
        clipboard->setText(lines.join('\n'));
    }
}


QVector<int> ContextMenuCleanerTab::selectedEntryIndexes(const MenuArea area) const
{
    const AreaWidgets* areaWidgets = widgetsForArea(area);
    QVector<int> indexes;
    if (areaWidgets == nullptr || areaWidgets->table == nullptr || areaWidgets->table->selectionModel() == nullptr)
    {
        return indexes;
    }

    const QModelIndexList kSelectedRows = areaWidgets->table->selectionModel()->selectedRows();
    for (const QModelIndex& modelIndex : kSelectedRows)
    {
        const QTableWidgetItem* item = areaWidgets->table->item(modelIndex.row(), kColumnName);
        if (item == nullptr)
        {
            continue;
        }
        const int kEntryIndex = item->data(Qt::UserRole).toInt();
        if (!indexes.contains(kEntryIndex))
        {
            indexes.push_back(kEntryIndex);
        }
    }
    return indexes;
}

ContextMenuCleanerTab::AreaWidgets* ContextMenuCleanerTab::widgetsForArea(const MenuArea area)
{
    switch (area)
    {
    case MenuArea::kInternetExplorer:
        return &ieWidgets_;
    case MenuArea::kDesktop:
        return &desktopWidgets_;
    case MenuArea::kFile:
        return &fileWidgets_;
    case MenuArea::kUrlBinding:
        return &urlBindingWidgets_;
    case MenuArea::kOpenWith:
        return &openWithWidgets_;
    case MenuArea::kFormatMenu:
        return &formatMenuWidgets_;
    case MenuArea::kExplorerHome:
        return &explorerHomeWidgets_;
    }
    return &fileWidgets_;
}

const ContextMenuCleanerTab::AreaWidgets* ContextMenuCleanerTab::widgetsForArea(const MenuArea area) const
{
    switch (area)
    {
    case MenuArea::kInternetExplorer:
        return &ieWidgets_;
    case MenuArea::kDesktop:
        return &desktopWidgets_;
    case MenuArea::kFile:
        return &fileWidgets_;
    case MenuArea::kUrlBinding:
        return &urlBindingWidgets_;
    case MenuArea::kOpenWith:
        return &openWithWidgets_;
    case MenuArea::kFormatMenu:
        return &formatMenuWidgets_;
    case MenuArea::kExplorerHome:
        return &explorerHomeWidgets_;
    }
    return &fileWidgets_;
}

QString ContextMenuCleanerTab::areaTitle(const MenuArea area)
{
    switch (area)
    {
    case MenuArea::kInternetExplorer:
        return QStringLiteral("IE右键菜单");
    case MenuArea::kDesktop:
        return QStringLiteral("桌面右键菜单");
    case MenuArea::kFile:
        return QStringLiteral("文件右键菜单");
    case MenuArea::kUrlBinding:
        return QStringLiteral("URL 绑定");
    case MenuArea::kOpenWith:
        return QStringLiteral("文件打开方式");
    case MenuArea::kFormatMenu:
        return QStringLiteral("格式右键菜单");
    case MenuArea::kExplorerHome:
        return QStringLiteral("资源管理器主页第三方程序");
    }
    return QStringLiteral("文件右键菜单");
}

QString ContextMenuCleanerTab::areaIconPath(const MenuArea area)
{
    switch (area)
    {
    case MenuArea::kInternetExplorer:
        return QStringLiteral(":/Icon/process_list.svg");
    case MenuArea::kDesktop:
        return QStringLiteral(":/Icon/desktop_switch.svg");
    case MenuArea::kFile:
        return QStringLiteral(":/Icon/process_open_folder.svg");
    case MenuArea::kUrlBinding:
        return QStringLiteral(":/Icon/log_track.svg");
    case MenuArea::kOpenWith:
        return QStringLiteral(":/Icon/process_open_folder.svg");
    case MenuArea::kFormatMenu:
        return QStringLiteral(":/Icon/process_list.svg");
    case MenuArea::kExplorerHome:
        return QStringLiteral(":/Icon/desktop_switch.svg");
    }
    return QStringLiteral(":/Icon/process_open_folder.svg");
}

} // namespace ks::misc

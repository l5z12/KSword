
#include "KernelDock.h"
#include "../ui/DetailLayoutRegistry.h"

// ============================================================
// KernelDock.Runtime.cpp
// Purpose:
// 1) Carries the asynchronous refresh process for KernelDock;
// 2) Carry the reconstruction logic for three tables;
// 3) Handle detail linkage and parsing of the currently selected item.
// ============================================================

#include "KernelDockAtomWorker.h"
#include "KernelDockObjectNamespaceWorker.h"
#include "KernelDockQueryWorker.h"
#include "../ui/CodeEditorWidget.h"
#include "../Theme.h"

#include <QBrush>
#include <QLabel>
#include <QLineEdit>
#include <QMetaObject>
#include <QMap>
#include <QPointer>
#include <QPushButton>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTreeWidget>
#include <QTreeWidgetItem>

#include <algorithm> // std::count_if: counts failed items.
#include <limits>    // std::numeric_limits: Defines the sentinel value for tree nodes.
#include <thread>    // std::thread: Background refresh task.

using ksword::kernel_dock_internal::kernelText;

namespace
{
    // statusLabelStyle：
    // - Purpose: Unify status label color and font weight.
    QString statusLabelStyle(const QString& colorHex)
    {
        return QStringLiteral("color:%1;font-weight:600;").arg(colorHex);
    }

    // safeText：
    // - Purpose: Replace empty text with a placeholder to avoid blank fields in the details area.
    QString safeText(const QString& valueText, const QString& fallbackText)
    {
        return valueText.trimmed().isEmpty() ? fallbackText : valueText;
    }

    QString safeText(const QString& valueText)
    {
        return safeText(valueText, kernelText("kernel.runtime.placeholder.empty", QStringLiteral("<空>")));
    }

    QString emptyText()
    {
        return kernelText("kernel.runtime.placeholder.empty", QStringLiteral("<空>"));
    }

    // ObjectNamespaceColumn: Object namespace tree column indices.
    enum class ObjectNamespaceColumn : int
    {
        kName = 0,
        kType,
        kPathOrScope,
        kStatus,
        kSymbolicTarget,
        kCount
    };

    // ObjectNamespaceNodeKind: Type of a node in the object namespace tree.
    enum class ObjectNamespaceNodeKind : int
    {
        kRoot = 0,
        kDirectory,
        kObjectEntry
    };

    // Custom roles for the object namespace tree:
    // - SourceIndexRole: The index in m_objectNamespaceRows corresponding to the object node.
    // - NodeKindRole: Node type (root/directory/object).
    // - NodePathRole: Node path (root path/directory path/full object path).
    // - NodeDescriptionRole: Supplementary description text for the node.
    constexpr int kSourceIndexRole = Qt::UserRole + 1;
    constexpr int kNodeKindRole = Qt::UserRole + 2;
    constexpr int kNodePathRole = Qt::UserRole + 3;
    constexpr int kNodeDescriptionRole = Qt::UserRole + 4;

    // kInvalidSourceIndex: sentinel value used when a tree node has no bound object record.
    constexpr qulonglong kInvalidSourceIndex = std::numeric_limits<qulonglong>::max();

    // leafNameFromObjectPath：
    // - Purpose: Extracts the last segment of the object path for tree node display.
    QString leafNameFromObjectPath(const QString& fullPathText)
    {
        const int kSlashIndex = fullPathText.lastIndexOf('\\');
        if (kSlashIndex < 0)
        {
            return fullPathText;
        }
        if (kSlashIndex + 1 >= fullPathText.size())
        {
            return fullPathText;
        }
        return fullPathText.mid(kSlashIndex + 1);
    }

    // appendPropertyRow：
    // - Purpose: Append a "field name + field value" record to the property table and set it as read-only.
    void appendPropertyRow(QTableWidget* propertyTable, const QString& fieldNameText, const QString& fieldValueText)
    {
        if (propertyTable == nullptr)
        {
            return;
        }

        const int kRowIndex = propertyTable->rowCount();
        propertyTable->insertRow(kRowIndex);

        auto* nameItem = new QTableWidgetItem(fieldNameText);
        auto* valueItem = new QTableWidgetItem(fieldValueText);

        nameItem->setFlags(nameItem->flags() & ~Qt::ItemIsEditable);
        valueItem->setFlags(valueItem->flags() & ~Qt::ItemIsEditable);

        propertyTable->setItem(kRowIndex, 0, nameItem);
        propertyTable->setItem(kRowIndex, 1, valueItem);
    }

    // findFirstEntryItem：
    // - Purpose: Find the node in the tree containing the first bound object record.
    // - Returns: the node pointer if found; otherwise nullptr.
    QTreeWidgetItem* findFirstEntryItem(QTreeWidget* treeWidget)
    {
        if (treeWidget == nullptr)
        {
            return nullptr;
        }

        for (int rootIndex = 0; rootIndex < treeWidget->topLevelItemCount(); ++rootIndex)
        {
            QTreeWidgetItem* rootItem = treeWidget->topLevelItem(rootIndex);
            if (rootItem == nullptr)
            {
                continue;
            }

            for (int directoryIndex = 0; directoryIndex < rootItem->childCount(); ++directoryIndex)
            {
                QTreeWidgetItem* directoryItem = rootItem->child(directoryIndex);
                if (directoryItem == nullptr)
                {
                    continue;
                }

                for (int entryIndex = 0; entryIndex < directoryItem->childCount(); ++entryIndex)
                {
                    QTreeWidgetItem* entryItem = directoryItem->child(entryIndex);
                    if (entryItem == nullptr)
                    {
                        continue;
                    }

                    bool convertOk = false;
                    const qulonglong kSourceIndex = entryItem->data(0, kSourceIndexRole).toULongLong(&convertOk);
                    if (convertOk && kSourceIndex != kInvalidSourceIndex)
                    {
                        return entryItem;
                    }
                }
            }
        }

        return nullptr;
    }

    // AtomColumn: Atom table column index.
    enum class AtomColumn : int
    {
        kValue = 0,
        kHex,
        kName,
        kSource,
        kStatus,
        kCount
    };

    // NtQueryColumn: Historical NtQuery table column index.
    enum class NtQueryColumn : int
    {
        kCategory = 0,
        kFunction,
        kQueryItem,
        kStatus,
        kSummary,
        kCount
    };
}

void KernelDock::refreshObjectNamespaceAsync()
{
    if (objectNamespaceRefreshRunning_.exchange(true))
    {
        KLogEvent skipEvent;
        dbg << skipEvent << "[KernelDock] 对象命名空间刷新被忽略：已有任务运行。" << eol;
        return;
    }

    refreshObjectNamespaceButton_->setEnabled(false);
    objectNamespaceStatusLabel_->setText(kernelText("kernel.runtime.object_namespace.status.refreshing", QStringLiteral("状态：刷新中...")));
    objectNamespaceStatusLabel_->setStyleSheet(statusLabelStyle(ksword_theme::kPrimaryBlueHex));

    QPointer<KernelDock> guardThis(this);
    std::thread([guardThis]() {
        std::vector<KernelObjectNamespaceEntry> resultRows;
        QString errorText;
        const bool kSuccess = runObjectNamespaceSnapshotTask(resultRows, errorText);

        QMetaObject::invokeMethod(guardThis, [guardThis, kSuccess, errorText, resultRows = std::move(resultRows)]() mutable {
            if (guardThis == nullptr)
            {
                return;
            }

            guardThis->objectNamespaceRefreshRunning_.store(false);
            guardThis->refreshObjectNamespaceButton_->setEnabled(true);

            if (!kSuccess)
            {
                guardThis->objectNamespaceStatusLabel_->setText(kernelText("kernel.runtime.object_namespace.status.failed", QStringLiteral("状态：刷新失败")));
                guardThis->objectNamespaceStatusLabel_->setStyleSheet(statusLabelStyle(ksword_theme::errorHex()));
                guardThis->objectNamespaceDetailEditor_->setText(errorText);

                KLogEvent failEvent;
                err << failEvent
                    << "[KernelDock] 对象命名空间刷新失败: "
                    << errorText.toStdString()
                    << eol;
                return;
            }

            guardThis->objectNamespaceRows_ = std::move(resultRows);
            guardThis->rebuildObjectNamespaceTable(guardThis->objectNamespaceFilterEdit_->text().trimmed());

            const std::size_t kFailedCount = static_cast<std::size_t>(
                std::count_if(
                    guardThis->objectNamespaceRows_.begin(),
                    guardThis->objectNamespaceRows_.end(),
                    [](const KernelObjectNamespaceEntry& entry) {
                        return !entry.querySucceeded;
                    }));

            guardThis->objectNamespaceStatusLabel_->setText(
                kernelText("kernel.runtime.object_namespace.status.summary", QStringLiteral("状态：已刷新 %1 项，异常 %2 项"))
                .arg(guardThis->objectNamespaceRows_.size())
                .arg(kFailedCount));
            guardThis->objectNamespaceStatusLabel_->setStyleSheet(
                statusLabelStyle(kFailedCount == 0 ? ksword_theme::successHex() : ksword_theme::warningHex()));

            if (guardThis->objectNamespaceTree_->topLevelItemCount() > 0)
            {
                guardThis->selectFirstObjectNamespaceEntryItem();
            }
            else
            {
                guardThis->rebuildObjectNamespacePropertyTable(
                    nullptr,
                    kernelText("kernel.runtime.placeholder.no_visible_nodes", QStringLiteral("<无可见节点>")),
                    kernelText("kernel.runtime.placeholder.hint", QStringLiteral("提示")),
                    kernelText("kernel.runtime.placeholder.none", QStringLiteral("<无>")),
                    kernelText("kernel.runtime.object_namespace.empty.filtered", QStringLiteral("当前筛选条件下无可见对象记录。")));
                guardThis->objectNamespaceDetailEditor_->setText(kernelText("kernel.runtime.object_namespace.empty.filtered", QStringLiteral("当前筛选条件下无可见对象记录。")));
            }

            KLogEvent doneEvent;
            info << doneEvent
                << "[KernelDock] 对象命名空间刷新完成, total="
                << guardThis->objectNamespaceRows_.size()
                << ", failed="
                << kFailedCount
                << eol;
        }, Qt::QueuedConnection);
    }).detach();
}

void KernelDock::refreshAtomTableAsync()
{
    if (atomRefreshRunning_.exchange(true))
    {
        KLogEvent skipEvent;
        dbg << skipEvent << "[KernelDock] 原子表刷新被忽略：已有任务运行。" << eol;
        return;
    }

    refreshAtomButton_->setEnabled(false);
    atomStatusLabel_->setText(kernelText("kernel.runtime.atom.status.refreshing", QStringLiteral("状态：刷新中...")));
    atomStatusLabel_->setStyleSheet(statusLabelStyle(ksword_theme::kPrimaryBlueHex));

    QPointer<KernelDock> guardThis(this);
    std::thread([guardThis]() {
        std::vector<KernelAtomEntry> resultRows;
        QString errorText;
        const bool kSuccess = runAtomTableSnapshotTask(resultRows, errorText);

        QMetaObject::invokeMethod(guardThis, [guardThis, kSuccess, errorText, resultRows = std::move(resultRows)]() mutable {
            if (guardThis == nullptr)
            {
                return;
            }

            guardThis->atomRefreshRunning_.store(false);
            guardThis->refreshAtomButton_->setEnabled(true);

            if (!kSuccess)
            {
                guardThis->atomStatusLabel_->setText(kernelText("kernel.runtime.atom.status.failed", QStringLiteral("状态：刷新失败")));
                guardThis->atomStatusLabel_->setStyleSheet(statusLabelStyle(ksword_theme::errorHex()));
                guardThis->atomDetailEditor_->setText(errorText);

                KLogEvent failEvent;
                err << failEvent
                    << "[KernelDock] 原子表刷新失败: "
                    << errorText.toStdString()
                    << eol;
                return;
            }

            guardThis->atomRows_ = std::move(resultRows);
            guardThis->rebuildAtomTable(guardThis->atomFilterEdit_->text().trimmed());
            guardThis->atomStatusLabel_->setText(
                kernelText("kernel.runtime.atom.status.summary", QStringLiteral("状态：已刷新 %1 项"))
                .arg(guardThis->atomRows_.size()));
            guardThis->atomStatusLabel_->setStyleSheet(statusLabelStyle(ksword_theme::successHex()));

            if (guardThis->atomTable_->rowCount() > 0)
            {
                guardThis->atomTable_->setCurrentCell(0, 0);
            }
            else
            {
                guardThis->atomDetailEditor_->setText(kernelText("kernel.runtime.atom.empty", QStringLiteral("当前环境未发现可见原子记录。")));
            }

            KLogEvent doneEvent;
            info << doneEvent
                << "[KernelDock] 原子表刷新完成, count="
                << guardThis->atomRows_.size()
                << eol;
        }, Qt::QueuedConnection);
    }).detach();
}

void KernelDock::refreshNtQueryAsync()
{
    if (ntQueryRefreshRunning_.exchange(true))
    {
        KLogEvent skipEvent;
        dbg << skipEvent << "[KernelDock] NtQuery 刷新被忽略：已有任务运行。" << eol;
        return;
    }

    refreshNtQueryButton_->setEnabled(false);
    ntQueryStatusLabel_->setText(kernelText("kernel.runtime.nt_query.status.refreshing", QStringLiteral("状态：刷新中...")));
    ntQueryStatusLabel_->setStyleSheet(statusLabelStyle(ksword_theme::kPrimaryBlueHex));

    QPointer<KernelDock> guardThis(this);
    std::thread([guardThis]() {
        std::vector<KernelNtQueryResultEntry> resultRows;
        QString errorText;
        const bool kSuccess = runNtQuerySnapshotTask(resultRows, errorText);

        QMetaObject::invokeMethod(guardThis, [guardThis, kSuccess, errorText, resultRows = std::move(resultRows)]() mutable {
            if (guardThis == nullptr)
            {
                return;
            }

            guardThis->ntQueryRefreshRunning_.store(false);
            guardThis->refreshNtQueryButton_->setEnabled(true);

            if (!kSuccess)
            {
                guardThis->ntQueryStatusLabel_->setText(kernelText("kernel.runtime.nt_query.status.failed", QStringLiteral("状态：刷新失败")));
                guardThis->ntQueryStatusLabel_->setStyleSheet(statusLabelStyle(ksword_theme::errorHex()));
                guardThis->ntQueryDetailEditor_->setText(errorText);

                KLogEvent failEvent;
                err << failEvent
                    << "[KernelDock] NtQuery 刷新失败: "
                    << errorText.toStdString()
                    << eol;
                return;
            }

            guardThis->ntQueryResults_ = std::move(resultRows);
            guardThis->rebuildNtQueryTable();

            int successCount = 0;
            for (const KernelNtQueryResultEntry& entry : guardThis->ntQueryResults_)
            {
                if (entry.statusCode >= 0)
                {
                    ++successCount;
                }
            }

            guardThis->ntQueryStatusLabel_->setText(
                kernelText("kernel.runtime.nt_query.status.summary", QStringLiteral("状态：已刷新 %1 项，成功 %2 项"))
                .arg(guardThis->ntQueryResults_.size())
                .arg(successCount));
            guardThis->ntQueryStatusLabel_->setStyleSheet(statusLabelStyle(ksword_theme::successHex()));

            if (guardThis->ntQueryTable_->rowCount() > 0)
            {
                guardThis->ntQueryTable_->setCurrentCell(0, 0);
            }
            else
            {
                guardThis->ntQueryDetailEditor_->setText(kernelText("kernel.runtime.nt_query.empty", QStringLiteral("无可展示的 NtQuery 结果。")));
            }

            KLogEvent doneEvent;
            info << doneEvent
                << "[KernelDock] NtQuery 刷新完成, total="
                << guardThis->ntQueryResults_.size()
                << ", success="
                << successCount
                << eol;
        }, Qt::QueuedConnection);
    }).detach();
}

void KernelDock::rebuildObjectNamespaceTable(const QString& filterKeyword)
{
    if (objectNamespaceTree_ == nullptr)
    {
        return;
    }

    objectNamespaceTree_->clear();

    // rootItemMap: Caches the 'root path -> root item' mapping to avoid creating root items repeatedly.
    QMap<QString, QTreeWidgetItem*> rootItemMap;
    // directoryItemMap: Caches the mapping from 'root path + directory path' to directory nodes to avoid creating duplicate directory nodes.
    QMap<QString, QTreeWidgetItem*> directoryItemMap;

    for (std::size_t sourceIndex = 0; sourceIndex < objectNamespaceRows_.size(); ++sourceIndex)
    {
        const KernelObjectNamespaceEntry& entry = objectNamespaceRows_[sourceIndex];
        const bool kMatched = filterKeyword.isEmpty()
            || entry.rootPathText.contains(filterKeyword, Qt::CaseInsensitive)
            || entry.scopeDescriptionText.contains(filterKeyword, Qt::CaseInsensitive)
            || entry.directoryPathText.contains(filterKeyword, Qt::CaseInsensitive)
            || entry.objectNameText.contains(filterKeyword, Qt::CaseInsensitive)
            || entry.objectTypeText.contains(filterKeyword, Qt::CaseInsensitive)
            || entry.fullPathText.contains(filterKeyword, Qt::CaseInsensitive)
            || entry.enumApiText.contains(filterKeyword, Qt::CaseInsensitive)
            || entry.symbolicLinkTargetText.contains(filterKeyword, Qt::CaseInsensitive)
            || entry.statusText.contains(filterKeyword, Qt::CaseInsensitive);
        if (!kMatched)
        {
            continue;
        }

        QTreeWidgetItem* rootItem = rootItemMap.value(entry.rootPathText, nullptr);
        if (rootItem == nullptr)
        {
            rootItem = new QTreeWidgetItem(objectNamespaceTree_);
            rootItem->setText(static_cast<int>(ObjectNamespaceColumn::kName), entry.rootPathText);
            rootItem->setText(static_cast<int>(ObjectNamespaceColumn::kType), kernelText("kernel.runtime.object_namespace.node.root_directory", QStringLiteral("根目录")));
            rootItem->setText(static_cast<int>(ObjectNamespaceColumn::kPathOrScope), safeText(entry.scopeDescriptionText));
            rootItem->setText(static_cast<int>(ObjectNamespaceColumn::kStatus), kernelText("kernel.runtime.object_namespace.node.root", QStringLiteral("根节点")));
            rootItem->setText(static_cast<int>(ObjectNamespaceColumn::kSymbolicTarget), kernelText("kernel.runtime.placeholder.none", QStringLiteral("<无>")));
            rootItem->setData(0, kSourceIndexRole, kInvalidSourceIndex);
            rootItem->setData(0, kNodeKindRole, static_cast<int>(ObjectNamespaceNodeKind::kRoot));
            rootItem->setData(0, kNodePathRole, entry.rootPathText);
            rootItem->setData(0, kNodeDescriptionRole, entry.scopeDescriptionText);
            rootItem->setForeground(
                static_cast<int>(ObjectNamespaceColumn::kType),
                QBrush(ksword_theme::primaryBlueColor));

            rootItemMap.insert(entry.rootPathText, rootItem);
        }

        const QString kDirectoryKeyText = entry.rootPathText + QChar('\n') + entry.directoryPathText;
        QTreeWidgetItem* directoryItem = directoryItemMap.value(kDirectoryKeyText, nullptr);
        if (directoryItem == nullptr)
        {
            directoryItem = new QTreeWidgetItem(rootItem);
            directoryItem->setText(
                static_cast<int>(ObjectNamespaceColumn::kName),
                leafNameFromObjectPath(entry.directoryPathText));
            directoryItem->setText(static_cast<int>(ObjectNamespaceColumn::kType), kernelText("kernel.runtime.object_namespace.node.directory", QStringLiteral("目录")));
            directoryItem->setText(static_cast<int>(ObjectNamespaceColumn::kPathOrScope), entry.directoryPathText);
            directoryItem->setText(static_cast<int>(ObjectNamespaceColumn::kStatus), kernelText("kernel.runtime.object_namespace.node.enumerated", QStringLiteral("已展开枚举")));
            directoryItem->setText(static_cast<int>(ObjectNamespaceColumn::kSymbolicTarget), kernelText("kernel.runtime.placeholder.none", QStringLiteral("<无>")));
            directoryItem->setData(0, kSourceIndexRole, kInvalidSourceIndex);
            directoryItem->setData(0, kNodeKindRole, static_cast<int>(ObjectNamespaceNodeKind::kDirectory));
            directoryItem->setData(0, kNodePathRole, entry.directoryPathText);
            directoryItem->setData(0, kNodeDescriptionRole, entry.scopeDescriptionText);
            directoryItem->setForeground(
                static_cast<int>(ObjectNamespaceColumn::kType),
                QBrush(ksword_theme::primaryBlueColor));

            directoryItemMap.insert(kDirectoryKeyText, directoryItem);
        }

        auto* objectItem = new QTreeWidgetItem(directoryItem);
        const QString kObjectNameText = entry.objectNameText.trimmed().isEmpty()
            ? kernelText("kernel.runtime.placeholder.unnamed_object", QStringLiteral("<未命名对象>"))
            : entry.objectNameText;
        objectItem->setText(static_cast<int>(ObjectNamespaceColumn::kName), kObjectNameText);
        objectItem->setText(static_cast<int>(ObjectNamespaceColumn::kType), safeText(entry.objectTypeText));
        objectItem->setText(static_cast<int>(ObjectNamespaceColumn::kPathOrScope), safeText(entry.fullPathText));
        objectItem->setText(static_cast<int>(ObjectNamespaceColumn::kStatus), safeText(entry.statusText));
        objectItem->setText(
            static_cast<int>(ObjectNamespaceColumn::kSymbolicTarget),
            safeText(entry.symbolicLinkTargetText));
        objectItem->setData(0, kSourceIndexRole, static_cast<qulonglong>(sourceIndex));
        objectItem->setData(0, kNodeKindRole, static_cast<int>(ObjectNamespaceNodeKind::kObjectEntry));
        objectItem->setData(0, kNodePathRole, entry.fullPathText);
        objectItem->setData(0, kNodeDescriptionRole, entry.scopeDescriptionText);

        if (!entry.querySucceeded)
        {
            objectItem->setForeground(
                static_cast<int>(ObjectNamespaceColumn::kStatus),
                QBrush(ksword_theme::warningAccentColor()));
        }
        else if (entry.isDirectory)
        {
            objectItem->setForeground(
                static_cast<int>(ObjectNamespaceColumn::kType),
                QBrush(ksword_theme::primaryBlueColor));
        }
    }

    if (!filterKeyword.isEmpty())
    {
        objectNamespaceTree_->expandAll();
    }
    else
    {
        for (int rootIndex = 0; rootIndex < objectNamespaceTree_->topLevelItemCount(); ++rootIndex)
        {
            QTreeWidgetItem* rootItem = objectNamespaceTree_->topLevelItem(rootIndex);
            if (rootItem == nullptr)
            {
                continue;
            }
            rootItem->setExpanded(true);
            for (int directoryIndex = 0; directoryIndex < rootItem->childCount(); ++directoryIndex)
            {
                QTreeWidgetItem* directoryItem = rootItem->child(directoryIndex);
                if (directoryItem != nullptr)
                {
                    directoryItem->setExpanded(false);
                }
            }
        }
    }

    if (objectNamespaceTree_->currentItem() == nullptr)
    {
        selectFirstObjectNamespaceEntryItem();
    }
}

void KernelDock::rebuildObjectNamespacePropertyTable(
    const KernelObjectNamespaceEntry* entry,
    const QString& nodeNameText,
    const QString& nodeTypeText,
    const QString& nodePathText,
    const QString& nodeDescriptionText)
{
    if (objectNamespacePropertyTable_ == nullptr)
    {
        return;
    }

    objectNamespacePropertyTable_->setRowCount(0);

    if (entry == nullptr)
    {
        appendPropertyRow(objectNamespacePropertyTable_, kernelText("kernel.runtime.object_namespace.property.node_name", QStringLiteral("节点名称")), safeText(nodeNameText));
        appendPropertyRow(objectNamespacePropertyTable_, kernelText("kernel.runtime.object_namespace.property.node_type", QStringLiteral("节点类型")), safeText(nodeTypeText));
        appendPropertyRow(objectNamespacePropertyTable_, kernelText("kernel.runtime.object_namespace.property.node_path", QStringLiteral("节点路径")), safeText(nodePathText));
        appendPropertyRow(objectNamespacePropertyTable_, kernelText("kernel.runtime.object_namespace.property.node_description", QStringLiteral("节点说明")), safeText(nodeDescriptionText));
        appendPropertyRow(
            objectNamespacePropertyTable_,
            kernelText("kernel.runtime.placeholder.hint", QStringLiteral("提示")),
            kernelText("kernel.runtime.object_namespace.property.tree_summary", QStringLiteral("当前节点是树层级摘要，展开下级并选择对象项可查看完整字段。")));
        return;
    }

    appendPropertyRow(
        objectNamespacePropertyTable_,
        kernelText("kernel.runtime.object_namespace.property.root_path", QStringLiteral("rootPathText（根目录）")),
        safeText(entry->rootPathText));
    appendPropertyRow(
        objectNamespacePropertyTable_,
        kernelText("kernel.runtime.object_namespace.property.scope_description", QStringLiteral("scopeDescriptionText（作用说明）")),
        safeText(entry->scopeDescriptionText));
    appendPropertyRow(
        objectNamespacePropertyTable_,
        kernelText("kernel.runtime.object_namespace.property.directory_path", QStringLiteral("directoryPathText（当前目录）")),
        safeText(entry->directoryPathText));
    appendPropertyRow(
        objectNamespacePropertyTable_,
        kernelText("kernel.runtime.object_namespace.property.object_name", QStringLiteral("objectNameText（对象名）")),
        safeText(entry->objectNameText));
    appendPropertyRow(
        objectNamespacePropertyTable_,
        kernelText("kernel.runtime.object_namespace.property.object_type", QStringLiteral("objectTypeText（对象类型）")),
        safeText(entry->objectTypeText));
    appendPropertyRow(
        objectNamespacePropertyTable_,
        kernelText("kernel.runtime.object_namespace.property.full_path", QStringLiteral("fullPathText（完整路径）")),
        safeText(entry->fullPathText));
    appendPropertyRow(
        objectNamespacePropertyTable_,
        kernelText("kernel.runtime.object_namespace.property.enum_api", QStringLiteral("enumApiText（枚举API）")),
        safeText(entry->enumApiText));
    appendPropertyRow(
        objectNamespacePropertyTable_,
        kernelText("kernel.runtime.object_namespace.property.symbolic_target", QStringLiteral("symbolicLinkTargetText（符号链接目标）")),
        safeText(entry->symbolicLinkTargetText));
    appendPropertyRow(
        objectNamespacePropertyTable_,
        kernelText("kernel.runtime.object_namespace.property.status_text", QStringLiteral("statusText（状态）")),
        safeText(entry->statusText));
    appendPropertyRow(
        objectNamespacePropertyTable_,
        kernelText("kernel.runtime.object_namespace.property.status_code", QStringLiteral("statusCode（NTSTATUS）")),
        QStringLiteral("0x%1").arg(static_cast<unsigned int>(entry->statusCode), 8, 16, QChar('0')).toUpper());
    appendPropertyRow(
        objectNamespacePropertyTable_,
        kernelText("kernel.runtime.object_namespace.property.query_succeeded", QStringLiteral("querySucceeded（查询成功）")),
        entry->querySucceeded ? QStringLiteral("true") : QStringLiteral("false"));
    appendPropertyRow(
        objectNamespacePropertyTable_,
        kernelText("kernel.runtime.object_namespace.property.is_directory", QStringLiteral("isDirectory（是否目录）")),
        entry->isDirectory ? QStringLiteral("true") : QStringLiteral("false"));
    appendPropertyRow(
        objectNamespacePropertyTable_,
        kernelText("kernel.runtime.object_namespace.property.is_symbolic_link", QStringLiteral("isSymbolicLink（是否符号链接）")),
        entry->isSymbolicLink ? QStringLiteral("true") : QStringLiteral("false"));
}

void KernelDock::selectFirstObjectNamespaceEntryItem()
{
    if (objectNamespaceTree_ == nullptr)
    {
        return;
    }

    QTreeWidgetItem* firstEntryItem = findFirstEntryItem(objectNamespaceTree_);
    if (firstEntryItem != nullptr)
    {
        objectNamespaceTree_->setCurrentItem(firstEntryItem, 0);
        return;
    }

    if (objectNamespaceTree_->topLevelItemCount() > 0)
    {
        objectNamespaceTree_->setCurrentItem(objectNamespaceTree_->topLevelItem(0), 0);
        return;
    }

    rebuildObjectNamespacePropertyTable(
        nullptr,
        kernelText("kernel.runtime.placeholder.no_node", QStringLiteral("<无节点>")),
        kernelText("kernel.runtime.placeholder.hint", QStringLiteral("提示")),
        kernelText("kernel.runtime.placeholder.none", QStringLiteral("<无>")),
        kernelText("kernel.runtime.object_namespace.empty.tree", QStringLiteral("当前对象命名空间树为空。")));
    objectNamespaceDetailEditor_->setText(kernelText("kernel.runtime.object_namespace.empty.tree", QStringLiteral("当前对象命名空间树为空。")));
}

void KernelDock::rebuildAtomTable(const QString& filterKeyword)
{
    ks::ui::DetailLayoutRegistry::prepareDataRebuild(atomDetailEditor_);
    if (atomTable_ == nullptr)
    {
        return;
    }

    atomTable_->setSortingEnabled(false);
    atomTable_->setRowCount(0);

    for (std::size_t sourceIndex = 0; sourceIndex < atomRows_.size(); ++sourceIndex)
    {
        const KernelAtomEntry& entry = atomRows_[sourceIndex];
        const QString kValueText = QString::number(entry.atomValue);
        const QString kHexText = QStringLiteral("0x%1")
            .arg(static_cast<unsigned int>(entry.atomValue), 4, 16, QChar('0'))
            .toUpper();

        const bool kMatched = filterKeyword.isEmpty()
            || kValueText.contains(filterKeyword, Qt::CaseInsensitive)
            || kHexText.contains(filterKeyword, Qt::CaseInsensitive)
            || entry.atomNameText.contains(filterKeyword, Qt::CaseInsensitive)
            || entry.sourceText.contains(filterKeyword, Qt::CaseInsensitive)
            || entry.statusText.contains(filterKeyword, Qt::CaseInsensitive);
        if (!kMatched)
        {
            continue;
        }

        const int kRowIndex = atomTable_->rowCount();
        atomTable_->insertRow(kRowIndex);

        auto* valueItem = new QTableWidgetItem(kValueText);
        valueItem->setData(Qt::UserRole, static_cast<qulonglong>(sourceIndex));
        auto* hexItem = new QTableWidgetItem(kHexText);
        auto* nameItem = new QTableWidgetItem(entry.atomNameText);
        auto* sourceItem = new QTableWidgetItem(entry.sourceText);
        auto* statusItem = new QTableWidgetItem(entry.statusText);

        valueItem->setFlags(valueItem->flags() & ~Qt::ItemIsEditable);
        hexItem->setFlags(hexItem->flags() & ~Qt::ItemIsEditable);
        nameItem->setFlags(nameItem->flags() & ~Qt::ItemIsEditable);
        sourceItem->setFlags(sourceItem->flags() & ~Qt::ItemIsEditable);
        statusItem->setFlags(statusItem->flags() & ~Qt::ItemIsEditable);

        if (!entry.querySucceeded)
        {
            statusItem->setForeground(QBrush(ksword_theme::warningAccentColor()));
        }

        atomTable_->setItem(kRowIndex, static_cast<int>(AtomColumn::kValue), valueItem);
        atomTable_->setItem(kRowIndex, static_cast<int>(AtomColumn::kHex), hexItem);
        atomTable_->setItem(kRowIndex, static_cast<int>(AtomColumn::kName), nameItem);
        atomTable_->setItem(kRowIndex, static_cast<int>(AtomColumn::kSource), sourceItem);
        atomTable_->setItem(kRowIndex, static_cast<int>(AtomColumn::kStatus), statusItem);
    }

    atomTable_->setSortingEnabled(true);
}

void KernelDock::rebuildNtQueryTable()
{
    ks::ui::DetailLayoutRegistry::prepareDataRebuild(ntQueryDetailEditor_);
    if (ntQueryTable_ == nullptr)
    {
        return;
    }

    ntQueryTable_->setSortingEnabled(false);
    ntQueryTable_->setRowCount(0);

    for (std::size_t sourceIndex = 0; sourceIndex < ntQueryResults_.size(); ++sourceIndex)
    {
        const KernelNtQueryResultEntry& entry = ntQueryResults_[sourceIndex];
        const int kRowIndex = ntQueryTable_->rowCount();
        ntQueryTable_->insertRow(kRowIndex);

        auto* categoryItem = new QTableWidgetItem(entry.categoryText);
        categoryItem->setData(Qt::UserRole, static_cast<qulonglong>(sourceIndex));
        auto* functionItem = new QTableWidgetItem(entry.functionNameText);
        auto* queryItem = new QTableWidgetItem(entry.queryItemText);
        auto* statusItem = new QTableWidgetItem(entry.statusText);
        auto* summaryItem = new QTableWidgetItem(entry.summaryText);

        categoryItem->setFlags(categoryItem->flags() & ~Qt::ItemIsEditable);
        functionItem->setFlags(functionItem->flags() & ~Qt::ItemIsEditable);
        queryItem->setFlags(queryItem->flags() & ~Qt::ItemIsEditable);
        statusItem->setFlags(statusItem->flags() & ~Qt::ItemIsEditable);
        summaryItem->setFlags(summaryItem->flags() & ~Qt::ItemIsEditable);

        if (entry.statusCode < 0)
        {
            statusItem->setForeground(QBrush(ksword_theme::warningAccentColor()));
        }

        ntQueryTable_->setItem(kRowIndex, static_cast<int>(NtQueryColumn::kCategory), categoryItem);
        ntQueryTable_->setItem(kRowIndex, static_cast<int>(NtQueryColumn::kFunction), functionItem);
        ntQueryTable_->setItem(kRowIndex, static_cast<int>(NtQueryColumn::kQueryItem), queryItem);
        ntQueryTable_->setItem(kRowIndex, static_cast<int>(NtQueryColumn::kStatus), statusItem);
        ntQueryTable_->setItem(kRowIndex, static_cast<int>(NtQueryColumn::kSummary), summaryItem);
    }

    ntQueryTable_->setSortingEnabled(true);
}

bool KernelDock::currentObjectNamespaceSourceIndex(std::size_t& sourceIndexOut) const
{
    sourceIndexOut = 0;

    if (objectNamespaceTree_ == nullptr)
    {
        return false;
    }

    QTreeWidgetItem* currentItem = objectNamespaceTree_->currentItem();
    if (currentItem == nullptr)
    {
        return false;
    }

    bool convertOk = false;
    const qulonglong kSourceIndex = currentItem->data(0, kSourceIndexRole).toULongLong(&convertOk);
    if (!convertOk || kSourceIndex == kInvalidSourceIndex)
    {
        return false;
    }

    sourceIndexOut = static_cast<std::size_t>(kSourceIndex);
    return sourceIndexOut < objectNamespaceRows_.size();
}

bool KernelDock::currentAtomSourceIndex(std::size_t& sourceIndexOut) const
{
    sourceIndexOut = 0;

    if (atomTable_ == nullptr)
    {
        return false;
    }

    const int kCurrentRow = atomTable_->currentRow();
    if (kCurrentRow < 0)
    {
        return false;
    }

    QTableWidgetItem* valueItem = atomTable_->item(kCurrentRow, static_cast<int>(AtomColumn::kValue));
    if (valueItem == nullptr)
    {
        return false;
    }

    sourceIndexOut = static_cast<std::size_t>(valueItem->data(Qt::UserRole).toULongLong());
    return sourceIndexOut < atomRows_.size();
}

const KernelObjectNamespaceEntry* KernelDock::currentObjectNamespaceEntry() const
{
    std::size_t sourceIndex = 0;
    if (!currentObjectNamespaceSourceIndex(sourceIndex))
    {
        return nullptr;
    }
    return &objectNamespaceRows_[sourceIndex];
}

const KernelAtomEntry* KernelDock::currentAtomEntry() const
{
    std::size_t sourceIndex = 0;
    if (!currentAtomSourceIndex(sourceIndex))
    {
        return nullptr;
    }
    return &atomRows_[sourceIndex];
}

void KernelDock::showObjectNamespaceDetailByCurrentRow()
{
    if (objectNamespaceDetailEditor_ == nullptr || objectNamespaceTree_ == nullptr)
    {
        return;
    }

    QTreeWidgetItem* currentItem = objectNamespaceTree_->currentItem();
    if (currentItem == nullptr)
    {
        rebuildObjectNamespacePropertyTable(
            nullptr,
            kernelText("kernel.runtime.placeholder.unselected_node", QStringLiteral("<未选择节点>")),
            kernelText("kernel.runtime.placeholder.hint", QStringLiteral("提示")),
            kernelText("kernel.runtime.placeholder.none", QStringLiteral("<无>")),
            kernelText("kernel.runtime.object_namespace.detail.select_node", QStringLiteral("请选择左侧树节点查看对象字段。")));
        objectNamespaceDetailEditor_->setText(kernelText("kernel.runtime.object_namespace.detail.initial", QStringLiteral("请选择对象命名空间树节点查看详情。")));
        return;
    }

    const QString kNodeNameText = safeText(currentItem->text(static_cast<int>(ObjectNamespaceColumn::kName)));
    const QString kNodeTypeText = safeText(currentItem->text(static_cast<int>(ObjectNamespaceColumn::kType)));
    const QString kNodePathText = safeText(currentItem->data(0, kNodePathRole).toString());
    const QString kNodeDescriptionText = safeText(currentItem->data(0, kNodeDescriptionRole).toString());

    const KernelObjectNamespaceEntry* entry = currentObjectNamespaceEntry();
    if (entry == nullptr)
    {
        rebuildObjectNamespacePropertyTable(
            nullptr,
            kNodeNameText,
            kNodeTypeText,
            kNodePathText,
            kNodeDescriptionText);
        objectNamespaceDetailEditor_->setText(
            kernelText("kernel.runtime.object_namespace.detail.node_summary", QStringLiteral(
                "当前节点名称: %1\n"
                "当前节点类型: %2\n"
                "当前节点路径: %3\n"
                "节点说明: %4\n\n"
                "提示: 请选择目录下具体对象项以查看完整对象字段。"))
            .arg(kNodeNameText, kNodeTypeText, kNodePathText, kNodeDescriptionText));
        return;
    }

    rebuildObjectNamespacePropertyTable(
        entry,
        kNodeNameText,
        kNodeTypeText,
        kNodePathText,
        kNodeDescriptionText);

    const QString kDetailText = kernelText("kernel.runtime.object_namespace.detail.full", QStringLiteral(
        "树节点名称: %1\n"
        "树节点类型: %2\n"
        "目录路径: %3\n"
        "作用说明: %4\n"
        "当前目录: %5\n"
        "对象名: %6\n"
        "对象类型: %7\n"
        "完整路径: %8\n"
        "枚举 API: %9\n"
        "符号链接目标: %10\n"
        "状态: %11\n"
        "是否目录: %12\n"
        "是否符号链接: %13\n\n"
        "Worker详情:\n%14"))
        .arg(
            kNodeNameText,
            kNodeTypeText,
            safeText(entry->rootPathText),
            safeText(entry->scopeDescriptionText),
            safeText(entry->directoryPathText),
            safeText(entry->objectNameText),
            safeText(entry->objectTypeText),
            safeText(entry->fullPathText),
            safeText(entry->enumApiText),
            safeText(entry->symbolicLinkTargetText),
            safeText(entry->statusText),
            entry->isDirectory
                ? kernelText("kernel.runtime.value.yes", QStringLiteral("是"))
                : kernelText("kernel.runtime.value.no", QStringLiteral("否")),
            entry->isSymbolicLink
                ? kernelText("kernel.runtime.value.yes", QStringLiteral("是"))
                : kernelText("kernel.runtime.value.no", QStringLiteral("否")),
            safeText(entry->detailText));

    objectNamespaceDetailEditor_->setText(kDetailText);
}

void KernelDock::showAtomDetailByCurrentRow()
{
    if (atomDetailEditor_ == nullptr)
    {
        return;
    }

    const KernelAtomEntry* entry = currentAtomEntry();
    if (entry == nullptr)
    {
        atomDetailEditor_->setText(kernelText("kernel.runtime.atom.detail.initial", QStringLiteral("请选择一条原子记录查看详情。")));
        return;
    }

    const QString kDetailText = kernelText("kernel.runtime.atom.detail.full", QStringLiteral(
        "Atom值: %1\n"
        "十六进制: 0x%2\n"
        "名称: %3\n"
        "来源: %4\n"
        "状态: %5\n\n"
        "Worker详情:\n%6"))
        .arg(entry->atomValue)
        .arg(static_cast<unsigned int>(entry->atomValue), 4, 16, QChar('0'))
        .arg(safeText(entry->atomNameText))
        .arg(safeText(entry->sourceText))
        .arg(safeText(entry->statusText))
        .arg(safeText(entry->detailText));

    atomDetailEditor_->setText(kDetailText);
}

void KernelDock::showNtQueryDetailByCurrentRow()
{
    if (ntQueryTable_ == nullptr || ntQueryDetailEditor_ == nullptr)
    {
        return;
    }

    const int kCurrentRow = ntQueryTable_->currentRow();
    if (kCurrentRow < 0)
    {
        ntQueryDetailEditor_->setText(kernelText("kernel.runtime.nt_query.detail.initial", QStringLiteral("请选择一条 NtQuery 结果查看详情。")));
        return;
    }

    QTableWidgetItem* categoryItem = ntQueryTable_->item(kCurrentRow, static_cast<int>(NtQueryColumn::kCategory));
    if (categoryItem == nullptr)
    {
        ntQueryDetailEditor_->setText(kernelText("kernel.runtime.nt_query.detail.no_row", QStringLiteral("当前行无有效数据。")));
        return;
    }

    const std::size_t kSourceIndex = static_cast<std::size_t>(categoryItem->data(Qt::UserRole).toULongLong());
    if (kSourceIndex >= ntQueryResults_.size())
    {
        ntQueryDetailEditor_->setText(kernelText("kernel.runtime.nt_query.detail.out_of_range", QStringLiteral("索引越界。")));
        return;
    }

    const KernelNtQueryResultEntry& entry = ntQueryResults_[kSourceIndex];
    const QString kDetailText = kernelText("kernel.runtime.nt_query.detail.full", QStringLiteral(
        "类别: %1\n"
        "函数: %2\n"
        "查询项: %3\n"
        "状态: %4\n"
        "摘要: %5\n\n"
        "详细输出:\n%6"))
        .arg(entry.categoryText)
        .arg(entry.functionNameText)
        .arg(entry.queryItemText)
        .arg(entry.statusText)
        .arg(entry.summaryText)
        .arg(entry.detailText);

    ntQueryDetailEditor_->setText(kDetailText);
}


#include "KernelDock.h"

// ============================================================
// KernelDock.ContextMenu.cpp
// Purpose:
// 1) Right-click menu for the object namespace tree.
// 2) Context menu for the atom table carrier;
// 3) Implement copy and quick actions for objects/atoms.
// ============================================================

#include "KernelDockAtomWorker.h"
#include "KernelHvmTab.h"
#include "KernelDockObjectNamespaceWorker.h"
#include "../ui/CodeEditorWidget.h"
#include "../Theme.h"

#include <QApplication>
#include <QClipboard>
#include <QDialog>
#include <QIcon>
#include <QLineEdit>
#include <QMenu>
#include <QModelIndex>
#include <QStringList>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTreeWidget>
#include <QTreeWidgetItem>
#include <QVBoxLayout>

using ksword::kernel_dock_internal::kernelText;

namespace
{
    // safeText：
    // - Purpose: Replace empty text with a placeholder during copy to prevent TSV field misalignment.
    QString safeText(const QString& valueText, const QString& fallbackText)
    {
        return valueText.trimmed().isEmpty() ? fallbackText : valueText;
    }

    QString safeText(const QString& valueText)
    {
        return safeText(valueText, kernelText("kernel.context.placeholder.empty", QStringLiteral("<空>")));
    }

    // isNtDevicePath：
    // - Purpose: Check if the path is an NT device path (\Device\...).
    bool isNtDevicePath(const QString& pathText)
    {
        return pathText.startsWith(QStringLiteral("\\Device\\"), Qt::CaseInsensitive);
    }

    // copyTextToClipboard：
    // - Purpose: Unified clipboard write logic.
    void copyTextToClipboard(const QString& contentText)
    {
        if (QApplication::clipboard() != nullptr)
        {
            QApplication::clipboard()->setText(contentText);
        }
    }

    void showHvmFeatureDialog(
        QWidget* parent,
        const KernelHvmTab::FeatureArea featureArea)
    {
        auto* dialog = new QDialog(parent);
        dialog->setAttribute(Qt::WA_DeleteOnClose);
        dialog->setModal(false);
        dialog->resize(1180, 760);
        switch (featureArea)
        {
        case KernelHvmTab::FeatureArea::kKept:
            dialog->setWindowTitle(
                kernelText(
                    "kernel.hvm.dialog.ept",
                    QStringLiteral("内核虚拟化 - EPT")));
            break;
        case KernelHvmTab::FeatureArea::kNestedVmx:
            dialog->setWindowTitle(
                kernelText(
                    "kernel.hvm.dialog.nested",
                    QStringLiteral("内核虚拟化 - Nested VMX")));
            break;
        case KernelHvmTab::FeatureArea::kEvmcs:
            dialog->setWindowTitle(
                kernelText(
                    "kernel.hvm.dialog.evmcs",
                    QStringLiteral("内核虚拟化 - Hyper-V eVMCS（partial）")));
            break;
        }
        auto* layout = new QVBoxLayout(dialog);
        layout->setContentsMargins(6, 6, 6, 6);
        layout->addWidget(
            new KernelHvmTab(featureArea, dialog),
            1);
        dialog->show();
        dialog->raise();
        dialog->activateWindow();
    }

    // treeItemAsTsv：
    // - Purpose: Serialize the current row of the tree node to TSV.
    QString treeItemAsTsv(const QTreeWidget* treeWidget, const QTreeWidgetItem* treeItem)
    {
        if (treeWidget == nullptr || treeItem == nullptr)
        {
            return QString();
        }

        QStringList fieldList;
        for (int columnIndex = 0; columnIndex < treeWidget->columnCount(); ++columnIndex)
        {
            fieldList.push_back(treeItem->text(columnIndex));
        }
        return fieldList.join('\t');
    }

    // objectNamespaceEntryAsTsv：
    // - Purpose: Serialize object namespace entries to TSV.
    QString objectNamespaceEntryAsTsv(const KernelObjectNamespaceEntry& entry)
    {
        return QStringLiteral("%1\t%2\t%3\t%4\t%5\t%6\t%7\t%8\t%9")
            .arg(
                safeText(entry.rootPathText),
                safeText(entry.scopeDescriptionText),
                safeText(entry.directoryPathText),
                safeText(entry.objectNameText),
                safeText(entry.objectTypeText),
                safeText(entry.fullPathText),
                safeText(entry.enumApiText),
                safeText(entry.symbolicLinkTargetText),
                safeText(entry.statusText));
    }

    // atomEntryAsTsv：
    // - Purpose: Serialize the atom entry to TSV.
    QString atomEntryAsTsv(const KernelAtomEntry& entry)
    {
        const QString kHexText = QStringLiteral("0x%1")
            .arg(static_cast<unsigned int>(entry.atomValue), 4, 16, QChar('0'))
            .toUpper();

        return QStringLiteral("%1\t%2\t%3\t%4\t%5")
            .arg(QString::number(entry.atomValue), kHexText, safeText(entry.atomNameText), safeText(entry.sourceText), safeText(entry.statusText));
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
}

void KernelDock::showObjectNamespaceContextMenu(const QPoint& localPosition)
{
    if (objectNamespaceTree_ == nullptr)
    {
        return;
    }

    QTreeWidgetItem* clickedItem = objectNamespaceTree_->itemAt(localPosition);
    const int kClickedColumn = objectNamespaceTree_->columnAt(localPosition.x());
    if (clickedItem != nullptr)
    {
        objectNamespaceTree_->setCurrentItem(clickedItem, kClickedColumn >= 0 ? kClickedColumn : 0);
    }

    QTreeWidgetItem* currentItem = objectNamespaceTree_->currentItem();
    const KernelObjectNamespaceEntry* entry = currentObjectNamespaceEntry();
    const bool kHasEntry = (entry != nullptr);
    const bool kHasTreeNode = (currentItem != nullptr);

    QMenu contextMenu(this);
    contextMenu.setStyleSheet(ksword_theme::contextMenuStyle());

    QAction* refreshAction = contextMenu.addAction(QIcon(":/Icon/process_refresh.svg"), kernelText("kernel.context.object.refresh", QStringLiteral("刷新对象命名空间")));
    contextMenu.addSeparator();

    QMenu* copyMenu = contextMenu.addMenu(QIcon(":/Icon/process_copy_row.svg"), kernelText("kernel.context.menu.copy", QStringLiteral("复制")));
    QAction* copyCellAction = copyMenu->addAction(QIcon(":/Icon/process_copy_cell.svg"), kernelText("kernel.context.menu.copy_cell", QStringLiteral("复制当前单元格")));
    QAction* copyObjectNameAction = copyMenu->addAction(kernelText("kernel.context.object.copy_name", QStringLiteral("复制对象名")));
    QAction* copyObjectTypeAction = copyMenu->addAction(kernelText("kernel.context.object.copy_type", QStringLiteral("复制对象类型")));
    QAction* copyFullPathAction = copyMenu->addAction(kernelText("kernel.context.object.copy_full_path", QStringLiteral("复制完整路径")));
    QAction* copySymbolicTargetAction = copyMenu->addAction(kernelText("kernel.context.object.copy_symbolic_target", QStringLiteral("复制符号链接目标")));
    QAction* copyEnumApiAction = copyMenu->addAction(kernelText("kernel.context.object.copy_enum_api", QStringLiteral("复制枚举 API")));
    QAction* copyRowAction = copyMenu->addAction(QIcon(":/Icon/process_copy_row.svg"), kernelText("kernel.context.menu.copy_row", QStringLiteral("复制当前行")));
    QAction* copySameRootRowsAction = copyMenu->addAction(kernelText("kernel.context.object.copy_same_directory", QStringLiteral("复制同目录路径全部行")));

    copyObjectNameAction->setEnabled(kHasEntry);
    copyObjectTypeAction->setEnabled(kHasEntry);
    copyFullPathAction->setEnabled(kHasEntry);
    copySymbolicTargetAction->setEnabled(kHasEntry && !entry->symbolicLinkTargetText.trimmed().isEmpty());
    copyEnumApiAction->setEnabled(kHasEntry);
    copyRowAction->setEnabled(kHasTreeNode);
    copySameRootRowsAction->setEnabled(kHasEntry);

    QMenu* operationMenu = contextMenu.addMenu(QIcon(":/Icon/process_tree.svg"), kernelText("kernel.context.object.operation", QStringLiteral("对象操作")));
    QAction* filterByRootAction = operationMenu->addAction(kernelText("kernel.context.object.filter_root", QStringLiteral("用目录路径过滤")));
    QAction* filterByDirectoryAction = operationMenu->addAction(kernelText("kernel.context.object.filter_directory", QStringLiteral("用当前目录过滤")));
    QAction* filterByObjectNameAction = operationMenu->addAction(kernelText("kernel.context.object.filter_name", QStringLiteral("用对象名过滤")));
    QAction* resolveSymbolicLinkAction = operationMenu->addAction(kernelText("kernel.context.object.resolve_symbolic_target", QStringLiteral("解析符号链接目标")));
    QAction* mapDosPathAction = operationMenu->addAction(kernelText("kernel.context.object.map_dos_path", QStringLiteral("尝试映射为 DOS 路径")));

    contextMenu.addSeparator();
    QMenu* moreActionsMenu = contextMenu.addMenu(
        kernelText(
            "kernel.context.more_actions",
            QStringLiteral("更多操作")));
    QMenu* virtualizationMenu = moreActionsMenu->addMenu(
        kernelText(
            "kernel.context.virtualization",
            QStringLiteral("虚拟化")));
    QAction* eptAction = virtualizationMenu->addAction(
        QStringLiteral("EPT"));
    // Remove "(partial)": vmcs02 merging, exit reflection, and shadow EPT are all implemented and verified. Keeping
    // this suffix misleads users into thinking the menu item is a stub. Keep the eVMCS item as it is still partial.
    QAction* nestedVmxAction = virtualizationMenu->addAction(
        QStringLiteral("Nested VMX"));
    QAction* evmcsAction = virtualizationMenu->addAction(
        QStringLiteral("Hyper-V eVMCS (partial)"));

    filterByRootAction->setEnabled(kHasEntry);
    filterByDirectoryAction->setEnabled(kHasEntry);
    filterByObjectNameAction->setEnabled(kHasEntry && !entry->objectNameText.trimmed().isEmpty());
    resolveSymbolicLinkAction->setEnabled(kHasEntry && entry->isSymbolicLink);
    mapDosPathAction->setEnabled(kHasEntry && (isNtDevicePath(entry->fullPathText) || isNtDevicePath(entry->symbolicLinkTargetText)));

    QAction* selectedAction = contextMenu.exec(objectNamespaceTree_->viewport()->mapToGlobal(localPosition));
    if (selectedAction == nullptr)
    {
        return;
    }

    KLogEvent menuEvent;
    info << menuEvent
        << "[KernelDock] 对象命名空间右键动作: "
        << selectedAction->text().toStdString()
        << eol;

    if (selectedAction == refreshAction)
    {
        refreshObjectNamespaceAsync();
        return;
    }

    if (selectedAction == eptAction)
    {
        showHvmFeatureDialog(
            this,
            KernelHvmTab::FeatureArea::kKept);
        return;
    }
    if (selectedAction == nestedVmxAction)
    {
        showHvmFeatureDialog(
            this,
            KernelHvmTab::FeatureArea::kNestedVmx);
        return;
    }
    if (selectedAction == evmcsAction)
    {
        showHvmFeatureDialog(
            this,
            KernelHvmTab::FeatureArea::kEvmcs);
        return;
    }

    if (selectedAction == copyCellAction)
    {
        QTreeWidgetItem* selectedTreeItem = objectNamespaceTree_->currentItem();
        if (selectedTreeItem != nullptr)
        {
            int currentColumn = objectNamespaceTree_->currentColumn();
            if (currentColumn < 0)
            {
                currentColumn = 0;
            }
            copyTextToClipboard(selectedTreeItem->text(currentColumn));
        }
        return;
    }

    if (selectedAction == copyRowAction)
    {
        QTreeWidgetItem* selectedTreeItem = objectNamespaceTree_->currentItem();
        if (kHasEntry)
        {
            copyTextToClipboard(objectNamespaceEntryAsTsv(*entry));
        }
        else if (selectedTreeItem != nullptr)
        {
            copyTextToClipboard(treeItemAsTsv(objectNamespaceTree_, selectedTreeItem));
        }
        return;
    }

    if (!kHasEntry)
    {
        return;
    }

    if (selectedAction == copyObjectNameAction)
    {
        copyTextToClipboard(entry->objectNameText);
        return;
    }
    if (selectedAction == copyObjectTypeAction)
    {
        copyTextToClipboard(entry->objectTypeText);
        return;
    }
    if (selectedAction == copyFullPathAction)
    {
        copyTextToClipboard(entry->fullPathText);
        return;
    }
    if (selectedAction == copySymbolicTargetAction)
    {
        copyTextToClipboard(entry->symbolicLinkTargetText);
        return;
    }
    if (selectedAction == copyEnumApiAction)
    {
        copyTextToClipboard(entry->enumApiText);
        return;
    }
    if (selectedAction == copySameRootRowsAction)
    {
        QStringList rowList;
        for (const KernelObjectNamespaceEntry& rowEntry : objectNamespaceRows_)
        {
            if (QString::compare(rowEntry.directoryPathText, entry->directoryPathText, Qt::CaseInsensitive) == 0)
            {
                rowList.push_back(objectNamespaceEntryAsTsv(rowEntry));
            }
        }
        copyTextToClipboard(rowList.join('\n'));
        return;
    }

    if (selectedAction == filterByRootAction)
    {
        objectNamespaceFilterEdit_->setText(entry->rootPathText);
        return;
    }
    if (selectedAction == filterByDirectoryAction)
    {
        objectNamespaceFilterEdit_->setText(entry->directoryPathText);
        return;
    }
    if (selectedAction == filterByObjectNameAction)
    {
        objectNamespaceFilterEdit_->setText(entry->objectNameText);
        return;
    }
    if (selectedAction == resolveSymbolicLinkAction)
    {
        QString targetText;
        QString statusText;
        const bool kResolveOk = queryObjectNamespaceSymbolicLinkTarget(entry->fullPathText, targetText, statusText);

        QString resultText = kernelText("kernel.context.object.resolve_detail", QStringLiteral(
            "符号链接路径: %1\n"
            "解析状态: %2\n"
            "目标路径: %3"))
            .arg(entry->fullPathText)
            .arg(statusText)
            .arg(kResolveOk ? targetText : kernelText("kernel.context.placeholder.resolve_failed", QStringLiteral("<解析失败>")));

        std::size_t sourceIndex = 0;
        if (kResolveOk && currentObjectNamespaceSourceIndex(sourceIndex))
        {
            objectNamespaceRows_[sourceIndex].symbolicLinkTargetText = targetText;
            QTreeWidgetItem* selectedTreeItem = objectNamespaceTree_->currentItem();
            if (selectedTreeItem != nullptr)
            {
                selectedTreeItem->setText(static_cast<int>(ObjectNamespaceColumn::kSymbolicTarget), targetText);
            }
        }

        showObjectNamespaceDetailByCurrentRow();
        objectNamespaceDetailEditor_->setText(resultText);
        return;
    }
    if (selectedAction == mapDosPathAction)
    {
        QString sourcePathText;
        if (isNtDevicePath(entry->fullPathText))
        {
            sourcePathText = entry->fullPathText;
        }
        else
        {
            sourcePathText = entry->symbolicLinkTargetText;
        }

        const std::vector<QString> kCandidateList = queryDosPathCandidatesByNtPath(sourcePathText);
        if (kCandidateList.empty())
        {
            objectNamespaceDetailEditor_->setText(
                kernelText("kernel.context.object.dos_mapping.none", QStringLiteral("路径: %1\n未找到可用 DOS 路径映射。"))
                .arg(sourcePathText));
            return;
        }

        QStringList candidateTextList;
        for (const QString& candidateText : kCandidateList)
        {
            candidateTextList.push_back(candidateText);
        }

        const QString kJoinedText = candidateTextList.join('\n');
        copyTextToClipboard(kJoinedText);
        objectNamespaceDetailEditor_->setText(
            kernelText("kernel.context.object.dos_mapping.found", QStringLiteral("路径: %1\n已找到 DOS 路径映射（并已复制）：\n%2"))
            .arg(sourcePathText, kJoinedText));
        return;
    }
}

void KernelDock::showAtomContextMenu(const QPoint& localPosition)
{
    if (atomTable_ == nullptr)
    {
        return;
    }

    const QModelIndex kClickedIndex = atomTable_->indexAt(localPosition);
    if (kClickedIndex.isValid())
    {
        atomTable_->setCurrentCell(kClickedIndex.row(), kClickedIndex.column());
    }

    const KernelAtomEntry* entry = currentAtomEntry();
    const bool kHasEntry = (entry != nullptr);

    QMenu contextMenu(this);
    contextMenu.setStyleSheet(ksword_theme::contextMenuStyle());

    QAction* refreshAction = contextMenu.addAction(QIcon(":/Icon/process_refresh.svg"), kernelText("kernel.context.atom.refresh", QStringLiteral("刷新原子表")));
    contextMenu.addSeparator();

    QMenu* copyMenu = contextMenu.addMenu(QIcon(":/Icon/process_copy_row.svg"), kernelText("kernel.context.menu.copy", QStringLiteral("复制")));
    QAction* copyCellAction = copyMenu->addAction(QIcon(":/Icon/process_copy_cell.svg"), kernelText("kernel.context.menu.copy_cell", QStringLiteral("复制当前单元格")));
    QAction* copyValueAction = copyMenu->addAction(kernelText("kernel.context.atom.copy_value", QStringLiteral("复制Atom值")));
    QAction* copyHexAction = copyMenu->addAction(kernelText("kernel.context.atom.copy_hex", QStringLiteral("复制十六进制")));
    QAction* copyNameAction = copyMenu->addAction(kernelText("kernel.context.atom.copy_name", QStringLiteral("复制名称")));
    QAction* copySourceAction = copyMenu->addAction(kernelText("kernel.context.atom.copy_source", QStringLiteral("复制来源")));
    QAction* copyRowAction = copyMenu->addAction(QIcon(":/Icon/process_copy_row.svg"), kernelText("kernel.context.menu.copy_row", QStringLiteral("复制当前行")));

    copyValueAction->setEnabled(kHasEntry);
    copyHexAction->setEnabled(kHasEntry);
    copyNameAction->setEnabled(kHasEntry);
    copySourceAction->setEnabled(kHasEntry);
    copyRowAction->setEnabled(kHasEntry);

    QMenu* operationMenu = contextMenu.addMenu(QIcon(":/Icon/process_threads.svg"), kernelText("kernel.context.atom.operation", QStringLiteral("原子操作")));
    QAction* filterByNameAction = operationMenu->addAction(kernelText("kernel.context.atom.filter_name", QStringLiteral("用名称过滤")));
    QAction* verifyByNameAction = operationMenu->addAction(kernelText("kernel.context.atom.verify_global_find", QStringLiteral("使用GlobalFindAtomW校验")));
    QAction* copySnippetAction = operationMenu->addAction(kernelText("kernel.context.atom.copy_snippet", QStringLiteral("复制调用代码片段")));

    filterByNameAction->setEnabled(kHasEntry && !entry->atomNameText.trimmed().isEmpty());
    verifyByNameAction->setEnabled(kHasEntry && !entry->atomNameText.trimmed().isEmpty());
    copySnippetAction->setEnabled(kHasEntry && !entry->atomNameText.trimmed().isEmpty());

    QAction* selectedAction = contextMenu.exec(atomTable_->viewport()->mapToGlobal(localPosition));
    if (selectedAction == nullptr)
    {
        return;
    }

    KLogEvent menuEvent;
    info << menuEvent
        << "[KernelDock] 原子表右键动作: "
        << selectedAction->text().toStdString()
        << eol;

    if (selectedAction == refreshAction)
    {
        refreshAtomTableAsync();
        return;
    }

    if (selectedAction == copyCellAction)
    {
        const int kRowIndex = atomTable_->currentRow();
        const int kColumnIndex = atomTable_->currentColumn();
        if (kRowIndex >= 0 && kColumnIndex >= 0)
        {
            QTableWidgetItem* cellItem = atomTable_->item(kRowIndex, kColumnIndex);
            if (cellItem != nullptr)
            {
                copyTextToClipboard(cellItem->text());
            }
        }
        return;
    }

    if (!kHasEntry)
    {
        return;
    }

    if (selectedAction == copyValueAction)
    {
        copyTextToClipboard(QString::number(entry->atomValue));
        return;
    }
    if (selectedAction == copyHexAction)
    {
        const QString kHexText = QStringLiteral("0x%1")
            .arg(static_cast<unsigned int>(entry->atomValue), 4, 16, QChar('0'))
            .toUpper();
        copyTextToClipboard(kHexText);
        return;
    }
    if (selectedAction == copyNameAction)
    {
        copyTextToClipboard(entry->atomNameText);
        return;
    }
    if (selectedAction == copySourceAction)
    {
        copyTextToClipboard(entry->sourceText);
        return;
    }
    if (selectedAction == copyRowAction)
    {
        copyTextToClipboard(atomEntryAsTsv(*entry));
        return;
    }

    if (selectedAction == filterByNameAction)
    {
        atomFilterEdit_->setText(entry->atomNameText);
        return;
    }
    if (selectedAction == verifyByNameAction)
    {
        std::uint16_t foundAtomValue = 0;
        QString verifyDetailText;
        const bool kVerifyOk = verifyGlobalAtomByName(entry->atomNameText, foundAtomValue, verifyDetailText);

        if (kVerifyOk)
        {
            for (int rowIndex = 0; rowIndex < atomTable_->rowCount(); ++rowIndex)
            {
                QTableWidgetItem* valueItem = atomTable_->item(rowIndex, static_cast<int>(AtomColumn::kValue));
                if (valueItem == nullptr)
                {
                    continue;
                }

                if (valueItem->text() == QString::number(foundAtomValue))
                {
                    atomTable_->setCurrentCell(rowIndex, static_cast<int>(AtomColumn::kValue));
                    break;
                }
            }
        }

        atomDetailEditor_->setText(verifyDetailText);
        return;
    }
    if (selectedAction == copySnippetAction)
    {
        QString escapedNameText = entry->atomNameText;
        escapedNameText.replace('\\', QStringLiteral("\\\\"));
        escapedNameText.replace('"', QStringLiteral("\\\""));

        const QString kSnippetText = QStringLiteral("ATOM atomValue = GlobalFindAtomW(L\"%1\");")
            .arg(escapedNameText);

        copyTextToClipboard(kSnippetText);
        atomDetailEditor_->setText(
            kernelText("kernel.context.atom.snippet_copied", QStringLiteral("已复制调用代码片段：\n%1"))
            .arg(kSnippetText));
        return;
    }
}

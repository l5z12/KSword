#include "HandleDock.h"

// ============================================================
// HandleDock.Actions.cpp
// Purpose:
// - Implements interaction actions for the handle module.
// - Retain only actions for displaying object type details, copying, jumping, and read-only assistance.
// - Decouple from the main UI file to control single-file size.
// ============================================================

#include <QApplication>
#include <QClipboard>
#include <QMessageBox>
#include <QStringList>
#include <QTreeWidget>
#include <QTreeWidgetItem>

namespace
{
    // boolText：
    // - Purpose: Convert the boolean value to Chinese 'Yes/No'.
    // - This file is implemented separately to avoid dependencies on the UI cpp's anonymous namespace.
    QString boolText(const bool value)
    {
        return value ? QStringLiteral("是") : QStringLiteral("否");
    }
}

void HandleDock::showObjectTypeDetailByCurrentRow()
{
    objectTypeDetailTable_->clear();
    if (objectTypeTable_ == nullptr || objectTypeTable_->currentItem() == nullptr)
    {
        return;
    }

    const QVariant kRowIndexValue =
        objectTypeTable_->currentItem()->data(static_cast<int>(ObjectTypeTableColumn::kTypeIndex), Qt::UserRole);
    if (!kRowIndexValue.isValid())
    {
        return;
    }
    const std::size_t kRowIndex = static_cast<std::size_t>(kRowIndexValue.toULongLong());
    if (kRowIndex >= objectTypeRows_.size())
    {
        return;
    }

    const HandleObjectTypeEntry& row = objectTypeRows_[kRowIndex];
    auto addDetailRow = [this](const QString& keyText, const QString& valueText)
        {
            auto* detailItem = new QTreeWidgetItem();
            detailItem->setText(0, keyText);
            detailItem->setText(1, valueText);
            objectTypeDetailTable_->addTopLevelItem(detailItem);
        };

    addDetailRow(QStringLiteral("类型编号"), QString::number(row.typeIndex));
    addDetailRow(QStringLiteral("类型名称"), row.typeNameText);
    addDetailRow(QStringLiteral("对象总数"), QString::number(row.totalObjectCount));
    addDetailRow(QStringLiteral("句柄总数"), QString::number(row.totalHandleCount));
    addDetailRow(QStringLiteral("访问掩码"), formatHex(row.validAccessMask, 0));
    addDetailRow(QStringLiteral("安全要求"), boolText(row.securityRequired));
    addDetailRow(QStringLiteral("维护句柄计数"), boolText(row.maintainHandleCount));
    addDetailRow(QStringLiteral("池类型"), QString::number(row.poolType));
    addDetailRow(QStringLiteral("默认分页池配额"), QString::number(row.defaultPagedPoolCharge));
    addDetailRow(QStringLiteral("默认非分页池配额"), QString::number(row.defaultNonPagedPoolCharge));
}

HandleDock::HandleRow* HandleDock::selectedHandleRow()
{
    QTreeWidgetItem* currentItem = tableWidget_->currentItem();
    if (currentItem == nullptr)
    {
        return nullptr;
    }
    if (currentItem->data(0, ks::handle::kHandleTreeItemKindRole).toInt() !=
        static_cast<int>(ks::handle::HandleTreeItemKind::kHandleRow))
    {
        return nullptr;
    }
    const QVariant kRowIndexValue = currentItem->data(0, ks::handle::kHandleTreeSourceRowIndexRole);
    if (!kRowIndexValue.isValid())
    {
        return nullptr;
    }
    const std::size_t kRowIndex = static_cast<std::size_t>(kRowIndexValue.toULongLong());
    if (kRowIndex >= allRows_.size())
    {
        return nullptr;
    }
    return &allRows_[kRowIndex];
}

void HandleDock::copyCurrentHandleCell()
{
    QTreeWidgetItem* currentItem = tableWidget_->currentItem();
    if (currentItem == nullptr)
    {
        return;
    }
    const int kColumnIndex = tableWidget_->currentColumn();
    if (kColumnIndex < 0)
    {
        return;
    }
    QApplication::clipboard()->setText(currentItem->text(kColumnIndex));
}

void HandleDock::copyCurrentHandleRow()
{
    QTreeWidgetItem* currentItem = tableWidget_->currentItem();
    if (currentItem == nullptr)
    {
        return;
    }
    QStringList textList;
    for (int columnIndex = 0; columnIndex < static_cast<int>(HandleTableColumn::kCount); ++columnIndex)
    {
        textList.push_back(currentItem->text(columnIndex));
    }
    QApplication::clipboard()->setText(textList.join('\t'));
}

void HandleDock::closeCurrentHandle()
{
    HandleRow* row = selectedHandleRow();
    if (row == nullptr)
    {
        return;
    }

    const QString kConfirmText = QStringLiteral(
        "确认关闭目标句柄？\nPID=%1\nHandle=%2\nTypeIndex=%3\n类型=%4\n对象名=%5")
        .arg(row->processId)
        .arg(formatHex(row->handleValue, 0))
        .arg(row->typeIndex)
        .arg(row->typeName)
        .arg(formatObjectNameDisplayText(*row));
    if (QMessageBox::question(
            this,
            QStringLiteral("关闭句柄"),
            kConfirmText,
            QMessageBox::Yes | QMessageBox::No,
            QMessageBox::No) != QMessageBox::Yes)
    {
        return;
    }

    std::string detailText;
    const bool kCloseOk = closeRemoteHandle(*row, detailText);
    KLogEvent closeEvent;
    (kCloseOk ? info : err) << closeEvent
        << "[HandleDock] closeCurrentHandle: pid="
        << row->processId
        << ", handle="
        << formatHex(row->handleValue, 0).toStdString()
        << ", typeIndex="
        << row->typeIndex
        << ", ok="
        << (kCloseOk ? "true" : "false")
        << ", detail="
        << detailText
        << eol;

    if (kCloseOk)
    {
        QMessageBox::information(this, QStringLiteral("关闭句柄"), QStringLiteral("句柄关闭成功。\n%1").arg(QString::fromStdString(detailText)));
        requestAsyncRefresh(true);
        return;
    }
    QMessageBox::warning(this, QStringLiteral("关闭句柄"), QStringLiteral("句柄关闭失败。\n%1").arg(QString::fromStdString(detailText)));
}

void HandleDock::closeSameTypeHandlesInCurrentProcess()
{
    HandleRow* selectedRow = selectedHandleRow();
    if (selectedRow == nullptr)
    {
        return;
    }

    std::vector<HandleRow> targetRows;
    targetRows.reserve(128);
    // The batch close range uses the complete snapshot m_allRows to avoid being affected by current filter conditions.
    for (const HandleRow& row : allRows_)
    {
        if (row.processId == selectedRow->processId && row.typeIndex == selectedRow->typeIndex)
        {
            targetRows.push_back(row);
        }
    }
    if (targetRows.empty())
    {
        return;
    }

    const QString kConfirmText = QStringLiteral(
        "确认批量关闭同类型句柄？\nPID=%1\nTypeIndex=%2\n类型=%3\n目标数量=%4")
        .arg(selectedRow->processId)
        .arg(selectedRow->typeIndex)
        .arg(selectedRow->typeName)
        .arg(targetRows.size());
    if (QMessageBox::question(
            this,
            QStringLiteral("批量关闭句柄"),
            kConfirmText,
            QMessageBox::Yes | QMessageBox::No,
            QMessageBox::No) != QMessageBox::Yes)
    {
        return;
    }

    std::size_t successCount = 0;
    std::size_t failCount = 0;
    std::string lastErrorText;
    for (const HandleRow& targetRow : targetRows)
    {
        std::string detailText;
        const bool kCloseOk = closeRemoteHandle(targetRow, detailText);
        if (kCloseOk)
        {
            ++successCount;
        }
        else
        {
            ++failCount;
            lastErrorText = detailText;
        }
    }

    KLogEvent batchCloseEvent;
    info << batchCloseEvent
        << "[HandleDock] closeSameTypeHandlesInCurrentProcess: pid="
        << selectedRow->processId
        << ", typeIndex="
        << selectedRow->typeIndex
        << ", total="
        << targetRows.size()
        << ", success="
        << successCount
        << ", fail="
        << failCount
        << ", lastError="
        << lastErrorText
        << eol;

    QMessageBox::information(
        this,
        QStringLiteral("批量关闭句柄"),
        QStringLiteral("执行完成。\n成功: %1\n失败: %2\n最后错误: %3")
        .arg(successCount)
        .arg(failCount)
        .arg(QString::fromStdString(lastErrorText)));

    requestAsyncRefresh(true);
}

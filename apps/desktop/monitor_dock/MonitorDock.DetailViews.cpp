#include "MonitorDock.Support.h"

namespace ksword::ui::monitor_dock
{
    // buildEtwRowDetailText：
    // - Purpose: Format a specific row of the ETW event table into readable detail text.
    // - Call: Reused when right-clicking 'View Returned Details' and double-clicking an event row.
    QString buildEtwRowDetailText(QTableWidget* eventTable, const int row)
    {
        if (eventTable == nullptr || row < 0 || row >= eventTable->rowCount())
        {
            return QString();
        }

        const auto kItemTextAt = [eventTable, row](const int column) -> QString {
            QTableWidgetItem* itemPointer = eventTable->item(row, column);
            return itemPointer != nullptr ? itemPointer->text() : QString();
        };

        QString detailJsonText;
        QTableWidgetItem* detailItem = eventTable->item(row, 5);
        if (detailItem != nullptr)
        {
            const QString kDetailFromRole = detailItem->data(Qt::UserRole).toString();
            detailJsonText = kDetailFromRole.trimmed().isEmpty() ? detailItem->text() : kDetailFromRole;
        }
        QString normalizedDetailText = detailJsonText;
        QString semanticResourceText;
        QString semanticActionText;
        QString semanticTargetText;
        QString semanticStatusText;
        if (!detailJsonText.trimmed().isEmpty())
        {
            QJsonParseError parseError;
            const QJsonDocument kJsonDocument = QJsonDocument::fromJson(detailJsonText.toUtf8(), &parseError);
            if (!kJsonDocument.isNull() && kJsonDocument.isObject())
            {
                normalizedDetailText = QString::fromUtf8(kJsonDocument.toJson(QJsonDocument::Indented));

                const QJsonObject kRootObject = kJsonDocument.object();
                const QJsonObject kSemanticObject = kRootObject.value(QStringLiteral("semantic")).toObject();
                semanticResourceText = kSemanticObject.value(QStringLiteral("resourceType")).toString();
                semanticActionText = kSemanticObject.value(QStringLiteral("action")).toString();
                semanticTargetText = kSemanticObject.value(QStringLiteral("target")).toString();
                semanticStatusText = kSemanticObject.value(QStringLiteral("status")).toString();
            }
        }

        QString contentText;
        contentText += QStringLiteral("时间(100ns)：%1\n").arg(kItemTextAt(0));
        contentText += QStringLiteral("Provider：%1\n").arg(kItemTextAt(1));
        contentText += QStringLiteral("事件ID：%1\n").arg(kItemTextAt(2));
        contentText += QStringLiteral("事件名：%1\n").arg(kItemTextAt(3));
        contentText += QStringLiteral("PID / TID：%1\n").arg(kItemTextAt(4));
        contentText += QStringLiteral("ActivityId：%1\n").arg(kItemTextAt(6));
        if (!semanticResourceText.trimmed().isEmpty()
            || !semanticActionText.trimmed().isEmpty()
            || !semanticTargetText.trimmed().isEmpty()
            || !semanticStatusText.trimmed().isEmpty())
        {
            contentText += QStringLiteral("\n========== 语义摘要 ==========\n");
            contentText += QStringLiteral("资源类型：%1\n").arg(
                semanticResourceText.trimmed().isEmpty() ? QStringLiteral("<未知>") : semanticResourceText);
            contentText += QStringLiteral("动作：%1\n").arg(
                semanticActionText.trimmed().isEmpty() ? QStringLiteral("<未知>") : semanticActionText);
            contentText += QStringLiteral("目标：%1\n").arg(
                semanticTargetText.trimmed().isEmpty() ? QStringLiteral("<未知>") : semanticTargetText);
            contentText += QStringLiteral("状态：%1\n").arg(
                semanticStatusText.trimmed().isEmpty() ? QStringLiteral("<未知>") : semanticStatusText);
        }
        contentText += QStringLiteral("\n========== 返回详情 ==========\n");
        contentText += normalizedDetailText.trimmed().isEmpty() ? QStringLiteral("<空>") : normalizedDetailText;
        return contentText;
    }

    // buildWmiRowDetailText：
    // - Purpose: Format a specific row of the WMI result table into readable detail text.
    // - Call: Reused for right-clicking 'View Return Details', double-clicking an event row, and the text view window.
    QString buildWmiRowDetailText(QTableWidget* eventTable, const int row)
    {
        if (eventTable == nullptr || row < 0 || row >= eventTable->rowCount())
        {
            return QString();
        }

        const auto kItemTextAt = [eventTable, row](const int column) -> QString {
            QTableWidgetItem* itemPointer = eventTable->item(row, column);
            return itemPointer != nullptr ? itemPointer->text() : QString();
        };

        QString contentText;
        contentText += QStringLiteral("时间戳：%1\n").arg(kItemTextAt(0));
        contentText += QStringLiteral("事件来源：%1\n").arg(kItemTextAt(1));
        contentText += QStringLiteral("事件类：%1\n").arg(kItemTextAt(2));
        contentText += QStringLiteral("PID / 进程：%1\n").arg(kItemTextAt(3));
        contentText += QStringLiteral("\n========== 返回详情 ==========\n");
        contentText += kItemTextAt(4).trimmed().isEmpty() ? QStringLiteral("<空>") : kItemTextAt(4);
        return contentText;
    }
}

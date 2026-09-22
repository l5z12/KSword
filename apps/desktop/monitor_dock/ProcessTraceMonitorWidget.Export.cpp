#include "ProcessTraceMonitorWidget.h"
#include "../Theme.h"

// ============================================================
// ProcessTraceMonitorWidget.Export.cpp
// Purpose:
// 1) Implement the right-click menu for the event table and result export.
// 2) Keep Actions.cpp under 1000 lines to satisfy project splitting standards.
// 3) Reuse the process detail navigation logic to facilitate result linkage.
// ============================================================

#include "MonitorTextViewer.h"
#include "../online_scan/SandboxUploadActions.h"
#include "../process_dock/ProcessDetailWindow.h"

#include <QApplication>
#include <QClipboard>
#include <QDateTime>
#include <QFile>
#include <QFileDialog>
#include <QJsonDocument>
#include <QJsonParseError>
#include <QMenu>
#include <QMessageBox>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTextStream>

#include <algorithm>
#include <string>

namespace
{
    // openProcessDetailWindow：
    // - Purpose: Open process detail window by PID.
    // - Usage: Reused by the 'Go to Process Details' option in the event table's right-click menu.
    void openProcessDetailWindow(QWidget* parentWidget, const std::uint32_t pidValue)
    {
        if (pidValue == 0)
        {
            return;
        }

        // Right-click jump in the event table must return to the UI quickly:
        // - Do not perform queryProcessStaticDetailByPid here;
        // - The details window asynchronously fills slow fields in the background and loads heavy tabs as needed.
        ks::process::ProcessRecord record;
        record.pid = pidValue;
        record.processName = ks::process::getProcessNameByPid(pidValue);
        if (record.processName.empty())
        {
            record.processName = "PID_" + std::to_string(pidValue);
        }

        ProcessDetailWindow* detailWindow = new ProcessDetailWindow(record, nullptr);
        detailWindow->setAttribute(Qt::WA_DeleteOnClose, true);
        detailWindow->show();
        detailWindow->raise();
        detailWindow->activateWindow();
    }

    // extractPidFromPidTidText：
    // - Purpose: Extract the first part (PID) from "PID / TID" text.
    // - Call: Used when jumping to process details via right-click on the event table.
    bool extractPidFromPidTidText(const QString& pidTidText, std::uint32_t* pidOut)
    {
        if (pidOut == nullptr)
        {
            return false;
        }

        const QString kPidText = pidTidText.section('/', 0, 0).trimmed();
        bool parseOk = false;
        const std::uint32_t kPidValue = kPidText.toUInt(&parseOk, 10);
        if (!parseOk || kPidValue == 0)
        {
            return false;
        }

        *pidOut = kPidValue;
        return true;
    }
}

void ProcessTraceMonitorWidget::showEventContextMenu(const QPoint& position)
{
    if (eventTable_ == nullptr)
    {
        return;
    }

    const QModelIndex kIndex = eventTable_->indexAt(position);
    if (!kIndex.isValid())
    {
        return;
    }

    const int kRow = kIndex.row();
    const int kColumn = kIndex.column();

    QMenu menu(this);
    menu.setStyleSheet(ksword_theme::contextMenuStyle());
    QAction* viewDetailAction = menu.addAction(QIcon(":/Icon/process_details.svg"), QStringLiteral("查看返回详情"));
    menu.addSeparator();
    QAction* copyDetailAction = menu.addAction(QIcon(":/Icon/log_copy.svg"), QStringLiteral("复制返回详情文本"));
    QAction* copyCellAction = menu.addAction(QIcon(":/Icon/log_copy.svg"), QStringLiteral("复制单元格"));
    QAction* copyRowAction = menu.addAction(QIcon(":/Icon/log_clipboard.svg"), QStringLiteral("复制整行"));
    menu.addSeparator();
    QAction* gotoProcessAction = menu.addAction(QIcon(":/Icon/process_details.svg"), QStringLiteral("转到进程详细信息"));
    ks::online_scan::addVirusTotalSandboxMenu(
        &menu,
        this,
        [this, kRow]() -> ks::online_scan::SandboxUploadTarget {
            // Input: Current right-clicked row in the process-oriented event table.
            // Processing: Prioritize extracting the process PID from the PID/TID column; if that fails, attempt the Root PID column.
            // Returns: the process image path and source text corresponding to the PID; if resolution fails, returns errorText, and the unified menu helper is responsible for displaying the popup.
            const auto kItemTextAt = [this, kRow](const int column) -> QString {
                QTableWidgetItem* itemPointer = eventTable_ != nullptr ? eventTable_->item(kRow, column) : nullptr;
                return itemPointer != nullptr ? itemPointer->text() : QString();
            };

            std::uint32_t pidValue = 0;
            if (!extractPidFromPidTidText(kItemTextAt(kEventColumnPidTid), &pidValue) &&
                !ks::online_scan::tryParsePidFromText(kItemTextAt(kEventColumnRootPid), &pidValue))
            {
                return {
                    QString(),
                    QStringLiteral("进程定向事件"),
                    QStringLiteral("当前事件行未解析出有效 PID 或 Root PID，无法上传发起进程文件。")
                };
            }

            const QString kProcessPath = QString::fromStdString(ks::process::queryProcessPathByPid(pidValue)).trimmed();
            if (kProcessPath.isEmpty())
            {
                return {
                    QString(),
                    QStringLiteral("进程定向事件 PID=%1").arg(pidValue),
                    QStringLiteral("无法解析 PID=%1 的进程镜像路径。进程可能已退出，或当前权限不足。").arg(pidValue)
                };
            }

            return {
                kProcessPath,
                QStringLiteral("进程定向事件 PID=%1").arg(pidValue),
                QString()
            };
        });

    QAction* selectedAction = menu.exec(eventTable_->viewport()->mapToGlobal(position));
    if (selectedAction == nullptr)
    {
        return;
    }

    if (selectedAction == viewDetailAction)
    {
        openEventDetailViewerForRow(kRow);
        return;
    }

    if (selectedAction == copyDetailAction)
    {
        const QString kDetailText = [this, kRow]() -> QString {
            const auto kItemTextAt = [this, kRow](const int currentColumn) -> QString {
                QTableWidgetItem* itemPointer = eventTable_->item(kRow, currentColumn);
                return itemPointer != nullptr ? itemPointer->text() : QString();
            };

            QString detailBodyText = kItemTextAt(kEventColumnDetail);
            QString normalizedDetailText = detailBodyText;
            QJsonParseError parseError;
            const QJsonDocument kJsonDocument = QJsonDocument::fromJson(detailBodyText.toUtf8(), &parseError);
            if (!kJsonDocument.isNull())
            {
                normalizedDetailText = QString::fromUtf8(kJsonDocument.toJson(QJsonDocument::Indented));
            }
            else
            {
                normalizedDetailText.replace(QStringLiteral(" ; "), QStringLiteral("\n"));
            }

            QString contentText;
            contentText += QStringLiteral("时间(100ns)：%1\n").arg(kItemTextAt(kEventColumnTime100ns));
            contentText += QStringLiteral("类型：%1\n").arg(kItemTextAt(kEventColumnType));
            contentText += QStringLiteral("Provider：%1\n").arg(kItemTextAt(kEventColumnProvider));
            contentText += QStringLiteral("事件ID：%1\n").arg(kItemTextAt(kEventColumnEventId));
            contentText += QStringLiteral("事件名：%1\n").arg(kItemTextAt(kEventColumnEventName));
            contentText += QStringLiteral("PID / TID：%1\n").arg(kItemTextAt(kEventColumnPidTid));
            contentText += QStringLiteral("进程：%1\n").arg(kItemTextAt(kEventColumnProcess));
            contentText += QStringLiteral("根PID：%1\n").arg(kItemTextAt(kEventColumnRootPid));
            contentText += QStringLiteral("关系：%1\n").arg(kItemTextAt(kEventColumnRelation));
            contentText += QStringLiteral("ActivityId：%1\n").arg(kItemTextAt(kEventColumnActivityId));
            contentText += QStringLiteral("\n========== 返回详情 ==========\n");
            contentText += normalizedDetailText.trimmed().isEmpty() ? QStringLiteral("<空>") : normalizedDetailText;
            return contentText;
        }();

        QApplication::clipboard()->setText(kDetailText);
        return;
    }

    if (selectedAction == copyCellAction)
    {
        QTableWidgetItem* itemPointer = eventTable_->item(kRow, kColumn);
        if (itemPointer != nullptr)
        {
            QApplication::clipboard()->setText(itemPointer->text());
        }
        return;
    }

    if (selectedAction == copyRowAction)
    {
        QStringList rowTextList;
        for (int currentColumn = 0; currentColumn < kEventColumnCount; ++currentColumn)
        {
            QTableWidgetItem* itemPointer = eventTable_->item(kRow, currentColumn);
            rowTextList << (itemPointer != nullptr ? itemPointer->text() : QString());
        }
        QApplication::clipboard()->setText(rowTextList.join('\t'));
        return;
    }

    if (selectedAction == gotoProcessAction)
    {
        QTableWidgetItem* pidItem = eventTable_->item(kRow, kEventColumnPidTid);
        std::uint32_t pidValue = 0;
        if (pidItem == nullptr || !extractPidFromPidTidText(pidItem->text(), &pidValue))
        {
            QMessageBox::information(this, QStringLiteral("进程跳转"), QStringLiteral("当前行未解析出有效 PID。"));
            return;
        }
        openProcessDetailWindow(this, pidValue);
    }
}

void ProcessTraceMonitorWidget::openEventDetailViewerForRow(const int row) const
{
    if (eventTable_ == nullptr || row < 0 || row >= eventTable_->rowCount())
    {
        return;
    }

    const auto kItemTextAt = [this, row](const int column) -> QString {
        QTableWidgetItem* itemPointer = eventTable_->item(row, column);
        return itemPointer != nullptr ? itemPointer->text() : QString();
    };

    QString detailText = kItemTextAt(kEventColumnDetail);
    QString normalizedDetailText = detailText;
    const QByteArray kDetailBytes = detailText.toUtf8();
    QJsonParseError parseError;
    const QJsonDocument kJsonDocument = QJsonDocument::fromJson(kDetailBytes, &parseError);
    if (!kJsonDocument.isNull())
    {
        normalizedDetailText = QString::fromUtf8(kJsonDocument.toJson(QJsonDocument::Indented));
    }
    else
    {
        normalizedDetailText.replace(QStringLiteral(" ; "), QStringLiteral("\n"));
    }

    QString contentText;
    contentText += QStringLiteral("时间(100ns)：%1\n").arg(kItemTextAt(kEventColumnTime100ns));
    contentText += QStringLiteral("类型：%1\n").arg(kItemTextAt(kEventColumnType));
    contentText += QStringLiteral("Provider：%1\n").arg(kItemTextAt(kEventColumnProvider));
    contentText += QStringLiteral("事件ID：%1\n").arg(kItemTextAt(kEventColumnEventId));
    contentText += QStringLiteral("事件名：%1\n").arg(kItemTextAt(kEventColumnEventName));
    contentText += QStringLiteral("PID / TID：%1\n").arg(kItemTextAt(kEventColumnPidTid));
    contentText += QStringLiteral("进程：%1\n").arg(kItemTextAt(kEventColumnProcess));
    contentText += QStringLiteral("根PID：%1\n").arg(kItemTextAt(kEventColumnRootPid));
    contentText += QStringLiteral("关系：%1\n").arg(kItemTextAt(kEventColumnRelation));
    contentText += QStringLiteral("ActivityId：%1\n").arg(kItemTextAt(kEventColumnActivityId));
    contentText += QStringLiteral("\n========== 返回详情 ==========\n");
    contentText += normalizedDetailText.trimmed().isEmpty() ? QStringLiteral("<空>") : normalizedDetailText;

    monitor_text_viewer::showReadOnlyTextWindow(
        const_cast<ProcessTraceMonitorWidget*>(this),
        QStringLiteral("进程定向监控详情 - %1").arg(kItemTextAt(kEventColumnEventName)),
        contentText,
        QStringLiteral("monitor://process-trace/row-%1.txt").arg(row + 1));
}

void ProcessTraceMonitorWidget::exportVisibleRowsToTsv()
{
    if (eventTable_ == nullptr || eventTable_->rowCount() == 0)
    {
        QMessageBox::information(this, QStringLiteral("导出结果"), QStringLiteral("当前没有可导出的事件。"));
        return;
    }

    int visibleCount = 0;
    for (int row = 0; row < eventTable_->rowCount(); ++row)
    {
        if (!eventTable_->isRowHidden(row))
        {
            ++visibleCount;
        }
    }
    if (visibleCount == 0)
    {
        QMessageBox::information(this, QStringLiteral("导出结果"), QStringLiteral("当前筛选结果为空，没有可导出的可见行。"));
        return;
    }

    const QString kDefaultFileName = QStringLiteral("process_trace_%1.tsv")
        .arg(QDateTime::currentDateTime().toString(QStringLiteral("yyyyMMdd_HHmmss")));
    const QString kPathText = QFileDialog::getSaveFileName(
        this,
        QStringLiteral("导出进程定向监控结果"),
        kDefaultFileName,
        QStringLiteral("TSV 文件 (*.tsv);;文本文件 (*.txt)"));
    if (kPathText.trimmed().isEmpty())
    {
        return;
    }

    QFile fileObject(kPathText);
    if (!fileObject.open(QIODevice::WriteOnly | QIODevice::Text | QIODevice::Truncate))
    {
        QMessageBox::warning(this, QStringLiteral("导出结果"), QStringLiteral("无法写入文件：%1").arg(kPathText));
        return;
    }

    QTextStream outputStream(&fileObject);

    QStringList headerTextList;
    for (int column = 0; column < kEventColumnCount; ++column)
    {
        QTableWidgetItem* headerItem = eventTable_->horizontalHeaderItem(column);
        headerTextList << (headerItem != nullptr ? headerItem->text() : QString());
    }
    outputStream << headerTextList.join('\t') << '\n';

    for (int row = 0; row < eventTable_->rowCount(); ++row)
    {
        if (eventTable_->isRowHidden(row))
        {
            continue;
        }

        QStringList rowTextList;
        for (int column = 0; column < kEventColumnCount; ++column)
        {
            QTableWidgetItem* itemPointer = eventTable_->item(row, column);
            rowTextList << (itemPointer != nullptr ? itemPointer->text().replace('\t', ' ') : QString());
        }
        outputStream << rowTextList.join('\t') << '\n';
    }

    fileObject.close();

    KLogEvent event;
    info << event
        << "[ProcessTraceMonitorWidget] 导出可见事件完成, path="
        << kPathText.toStdString()
        << ", visibleCount="
        << visibleCount
        << eol;

    QMessageBox::information(this, QStringLiteral("导出结果"), QStringLiteral("导出完成：%1").arg(kPathText));
}

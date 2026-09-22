#include "MonitorDock.Support.h"

using namespace ksword::ui::monitor_dock;

void MonitorDock::exportWmiRowsToTsv()
{
    if (wmiEventTable_ == nullptr || wmiEventTable_->rowCount() == 0)
    {
        KLogEvent event;
        dbg << event
            << "[MonitorDock] WMI导出取消：无可导出事件。"
            << eol;
        QMessageBox::information(this, QStringLiteral("导出WMI"), QStringLiteral("当前没有可导出的WMI事件。"));
        return;
    }

    int visibleCount = 0;
    for (int row = 0; row < wmiEventTable_->rowCount(); ++row)
    {
        if (!wmiEventTable_->isRowHidden(row))
        {
            ++visibleCount;
        }
    }
    if (visibleCount == 0)
    {
        KLogEvent event;
        dbg << event
            << "[MonitorDock] WMI导出取消：当前筛选后无可见事件。"
            << eol;
        QMessageBox::information(this, QStringLiteral("导出WMI"), QStringLiteral("当前筛选结果为空，没有可导出的WMI事件。"));
        return;
    }

    const QString kDefaultName = QStringLiteral("wmi_events_%1.tsv")
        .arg(QDateTime::currentDateTime().toString(QStringLiteral("yyyyMMdd_HHmmss")));

    const QString kPath = QFileDialog::getSaveFileName(
        this,
        QStringLiteral("导出WMI结果"),
        kDefaultName,
        QStringLiteral("TSV文件 (*.tsv);;文本文件 (*.txt)"));

    if (kPath.trimmed().isEmpty())
    {
        KLogEvent event;
        dbg << event
            << "[MonitorDock] WMI导出取消：用户未选择路径。"
            << eol;
        return;
    }

    QFile file(kPath);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text | QIODevice::Truncate))
    {
        KLogEvent event;
        err << event
            << "[MonitorDock] WMI导出失败：无法写入文件, path="
            << kPath.toStdString()
            << eol;
        QMessageBox::warning(this, QStringLiteral("导出WMI"), QStringLiteral("无法写入文件：%1").arg(kPath));
        return;
    }

    QTextStream out(&file);

    QStringList header;
    for (int col = 0; col < wmiEventTable_->columnCount(); ++col)
    {
        QTableWidgetItem* item = wmiEventTable_->horizontalHeaderItem(col);
        header << (item != nullptr ? item->text() : QString());
    }
    out << header.join('\t') << '\n';

    for (int row = 0; row < wmiEventTable_->rowCount(); ++row)
    {
        if (wmiEventTable_->isRowHidden(row))
        {
            continue;
        }

        QStringList values;
        for (int col = 0; col < wmiEventTable_->columnCount(); ++col)
        {
            QTableWidgetItem* item = wmiEventTable_->item(row, col);
            values << (item != nullptr ? item->text().replace('\t', ' ') : QString());
        }
        out << values.join('\t') << '\n';
    }

    file.close();

    KLogEvent event;
    info << event
        << "[MonitorDock] WMI导出完成:"
        << kPath.toStdString()
        << ", visibleRows="
        << visibleCount
        << eol;
    QMessageBox::information(this, QStringLiteral("导出WMI"), QStringLiteral("导出完成：%1").arg(kPath));
}

void MonitorDock::openWmiEventDetailViewerForRow(const int row) const
{
    const QString kDetailText = buildWmiRowDetailText(wmiEventTable_, row);
    if (kDetailText.trimmed().isEmpty())
    {
        return;
    }

    QString classText;
    if (wmiEventTable_ != nullptr)
    {
        QTableWidgetItem* classItem = wmiEventTable_->item(row, 2);
        if (classItem != nullptr)
        {
            classText = classItem->text().trimmed();
        }
    }

    monitor_text_viewer::showReadOnlyTextWindow(
        const_cast<MonitorDock*>(this),
        QStringLiteral("WMI 返回详情 - %1").arg(classText.isEmpty() ? QStringLiteral("事件") : classText),
        kDetailText,
        QStringLiteral("monitor://wmi/row-%1.txt").arg(row + 1));
}

void MonitorDock::showWmiEventContextMenu(const QPoint& position)
{
    const QModelIndex kIndex = wmiEventTable_->indexAt(position);
    if (!kIndex.isValid())
    {
        return;
    }

    const int kRow = kIndex.row();
    const int kCol = kIndex.column();

    QMenu menu(this);
    // Explicitly fill the menu background to avoid a black background caused by inheriting a transparent style in light mode.
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
            // Input: Current right-click row in the WMI event table.
            // Handling: Parse the PID from the PID/TID column and query the EXE path for that process.
            // Returns: VT upload target; if parsing fails, return errorText to avoid scattering duplicate popup logic.
            QTableWidgetItem* pidItem = wmiEventTable_ != nullptr
                ? wmiEventTable_->item(kRow, 3)
                : nullptr;
            std::uint32_t pidValue = 0;
            if (pidItem == nullptr || !ks::online_scan::tryParsePidFromText(pidItem->text(), &pidValue))
            {
                return {
                    QString(),
                    QStringLiteral("WMI 事件"),
                    QStringLiteral("当前 WMI 事件行未解析出有效 PID，无法上传发起进程文件。")
                };
            }

            const QString kProcessPath = QString::fromStdString(ks::process::queryProcessPathByPid(pidValue)).trimmed();
            if (kProcessPath.isEmpty())
            {
                return {
                    QString(),
                    QStringLiteral("WMI 事件 PID=%1").arg(pidValue),
                    QStringLiteral("无法解析 PID=%1 的进程镜像路径。进程可能已退出，或当前权限不足。").arg(pidValue)
                };
            }

            return {
                kProcessPath,
                QStringLiteral("WMI 事件 PID=%1").arg(pidValue),
                QString()
            };
        });

    QAction* action = menu.exec(wmiEventTable_->viewport()->mapToGlobal(position));
    if (action == nullptr)
    {
        KLogEvent event;
        dbg << event
            << "[MonitorDock] WMI事件右键菜单取消。"
            << eol;
        return;
    }

    if (action == viewDetailAction)
    {
        KLogEvent event;
        info << event
            << "[MonitorDock] WMI事件右键操作：查看返回详情, row="
            << kRow
            << eol;
        openWmiEventDetailViewerForRow(kRow);
        return;
    }

    if (action == copyDetailAction)
    {
        const QString kDetailText = buildWmiRowDetailText(wmiEventTable_, kRow);
        QApplication::clipboard()->setText(kDetailText);
        KLogEvent event;
        dbg << event
            << "[MonitorDock] WMI事件右键操作：复制返回详情文本, row="
            << kRow
            << eol;
        return;
    }

    if (action == copyCellAction)
    {
        QTableWidgetItem* item = wmiEventTable_->item(kRow, kCol);
        if (item != nullptr)
        {
            QApplication::clipboard()->setText(item->text());
        }
        KLogEvent event;
        dbg << event
            << "[MonitorDock] WMI事件右键操作：复制单元格, row="
            << kRow
            << ", col="
            << kCol
            << eol;
        return;
    }

    if (action == copyRowAction)
    {
        QStringList values;
        for (int i = 0; i < wmiEventTable_->columnCount(); ++i)
        {
            QTableWidgetItem* item = wmiEventTable_->item(kRow, i);
            values << (item != nullptr ? item->text() : QString());
        }
        QApplication::clipboard()->setText(values.join('\t'));
        KLogEvent event;
        dbg << event
            << "[MonitorDock] WMI事件右键操作：复制整行, row="
            << kRow
            << eol;
        return;
    }

    if (action == gotoProcessAction)
    {
        QTableWidgetItem* pidItem = wmiEventTable_->item(kRow, 3);
        if (pidItem == nullptr)
        {
            return;
        }

        std::uint32_t pid = 0;
        if (!parsePid(pidItem->text(), pid))
        {
            KLogEvent event;
            warn << event
                << "[MonitorDock] WMI事件右键操作失败：PID解析失败, text="
                << pidItem->text().toStdString()
                << eol;
            QMessageBox::information(this, QStringLiteral("WMI事件"), QStringLiteral("未解析到有效PID。"));
            return;
        }
        KLogEvent event;
        info << event
            << "[MonitorDock] WMI事件右键操作：转到进程详情, pid="
            << pid
            << eol;
        openProcessDetail(this, pid);
    }
}

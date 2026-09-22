#include "MonitorDock.Support.h"

using namespace ksword::ui::monitor_dock;

void MonitorDock::exportEtwRowsToTsv(const bool visibleOnly)
{
    bool hasArchiveRows = false;
    {
        std::lock_guard<std::mutex> lock(etwArchiveMutex_);
        hasArchiveRows = !etwArchiveDirectory_.trimmed().isEmpty()
            && etwArchiveNextSequence_ != 0;
    }

    if (hasArchiveRows)
    {
        const QString kDefaultName = QStringLiteral("etw_events_%1.tsv")
            .arg(QDateTime::currentDateTime().toString(QStringLiteral("yyyyMMdd_HHmmss")));
        const QString kPath = QFileDialog::getSaveFileName(
            this,
            QStringLiteral("导出ETW结果"),
            kDefaultName,
            QStringLiteral("TSV文件 (*.tsv);;文本文件 (*.txt)"));
        if (kPath.trimmed().isEmpty())
        {
            return;
        }

        QStringList header;
        if (etwEventTable_ != nullptr)
        {
            for (int col = 0; col < etwEventTable_->columnCount(); ++col)
            {
                QTableWidgetItem* item = etwEventTable_->horizontalHeaderItem(col);
                header << (item != nullptr ? item->text() : QString());
            }
        }
        if (header.isEmpty())
        {
            header = QStringList{
                QStringLiteral("时间"), QStringLiteral("Provider"), QStringLiteral("事件ID"),
                QStringLiteral("事件名称"), QStringLiteral("PID/TID"), QStringLiteral("详情"),
                QStringLiteral("ActivityId")
            };
        }

        const EtwSimpleFilterCompiled kPostSimpleFilter = etwPostSimpleFilterCompiled_;
        const std::vector<EtwFilterRuleGroupCompiled> kPostFilterGroups = etwPostFilterCompiledGroupList_;
        const bool kTimelineFilterActive = visibleOnly && isEtwTimelineFilterActive();
        const std::uint64_t kCaptureStart100ns = etwCaptureStartTime100ns_;
        const std::uint64_t kSelectionStart100ns = etwTimelineSelectionStart100ns_;
        const std::uint64_t kSelectionEnd100ns = etwTimelineSelectionEnd100ns_;
        const std::vector<std::pair<std::uint64_t, std::uint64_t>> kPauseIntervals =
            etwTimelinePauseIntervals_;
        const bool kCapturePaused = etwCapturePaused_.load();
        const std::uint64_t kActivePauseStart100ns = etwTimelinePauseTime100ns_;
        const std::uint64_t kSessionGeneration = etwArchiveSessionGeneration_.load(
            std::memory_order_relaxed);

        if (!beginEtwArchiveBackgroundTask())
        {
            return;
        }
        MonitorDock* taskOwner = this;
        const auto kTaskCompletion = std::shared_ptr<void>(
            reinterpret_cast<void*>(1),
            [taskOwner](void*) {
                taskOwner->endEtwArchiveBackgroundTask();
            });
        QPointer<MonitorDock> guardThis(this);
        std::thread([
            taskOwner,
            kTaskCompletion,
            guardThis,
            kPath,
            header,
            visibleOnly,
            kPostSimpleFilter,
            kPostFilterGroups,
            kTimelineFilterActive,
            kCaptureStart100ns,
            kSelectionStart100ns,
            kSelectionEnd100ns,
            kPauseIntervals,
            kCapturePaused,
            kActivePauseStart100ns,
            kSessionGeneration]() {
            const auto kShouldCancel = [taskOwner, kSessionGeneration]() {
                return taskOwner->etwArchiveSessionGeneration_.load(std::memory_order_relaxed)
                    != kSessionGeneration;
            };
            const auto kRawToTimelineTimestamp = [
                kCaptureStart100ns,
                kPauseIntervals,
                kCapturePaused,
                kActivePauseStart100ns](const std::uint64_t rawTimestamp100ns) {
                if (kCaptureStart100ns == 0 || rawTimestamp100ns <= kCaptureStart100ns)
                {
                    return kCaptureStart100ns;
                }
                std::uint64_t pausedDuration100ns = 0;
                for (const auto& pauseInterval : kPauseIntervals)
                {
                    if (pauseInterval.second <= pauseInterval.first
                        || rawTimestamp100ns <= pauseInterval.first)
                    {
                        continue;
                    }
                    pausedDuration100ns += std::min(rawTimestamp100ns, pauseInterval.second)
                        - pauseInterval.first;
                }
                if (kCapturePaused
                    && kActivePauseStart100ns != 0
                    && rawTimestamp100ns > kActivePauseStart100ns)
                {
                    pausedDuration100ns += rawTimestamp100ns - kActivePauseStart100ns;
                }
                const std::uint64_t kElapsed100ns = rawTimestamp100ns - kCaptureStart100ns;
                return kCaptureStart100ns
                    + (kElapsed100ns > pausedDuration100ns
                        ? kElapsed100ns - pausedDuration100ns
                        : 0);
            };

            if (kShouldCancel())
            {
                return;
            }
            taskOwner->finishEtwArchiveSession();
            if (kShouldCancel())
            {
                return;
            }

            QStringList segmentPaths;
            bool archiveWriteFailed = false;
            {
                std::lock_guard<std::mutex> lock(taskOwner->etwArchiveMutex_);
                segmentPaths = taskOwner->etwArchiveClosedSegmentPaths_;
                archiveWriteFailed = taskOwner->etwArchiveWriteFailed_;
            }

            QString errorText;
            std::uint64_t exportedRows = 0;
            std::uint64_t scannedRows = 0;
            std::uint64_t maxSequence = 0;
            QSaveFile file(kPath);
            if (archiveWriteFailed)
            {
                errorText = QStringLiteral("ETW 全量归档写入失败，无法保证导出完整性。");
            }
            else if (!file.open(QIODevice::WriteOnly | QIODevice::Text))
            {
                errorText = QStringLiteral("无法写入文件：%1").arg(kPath);
            }

            bool streamWriteFailed = false;
            if (errorText.isEmpty())
            {
                QTextStream out(&file);
                out << header.join(QChar(u'\t')) << QChar(u'\n');
                const auto kCleanTsvField = [](QString value) {
                    value.replace(QChar(u'\t'), QChar(u' '));
                    value.replace(QChar(u'\r'), QChar(u' '));
                    value.replace(QChar(u'\n'), QChar(u' '));
                    return value;
                };
                const auto kRowVisitor = [&](const EtwCapturedEventRow& row) {
                    bool matches = !visibleOnly
                        || etwFilterStageMatches(kPostSimpleFilter, kPostFilterGroups, row);
                    if (matches && kTimelineFilterActive)
                    {
                        const std::uint64_t kTimelineTimestamp100ns = kRawToTimelineTimestamp(row.timestampValue);
                        matches = kTimelineTimestamp100ns >= kSelectionStart100ns
                            && kTimelineTimestamp100ns <= kSelectionEnd100ns;
                    }
                    if (!matches)
                    {
                        return true;
                    }

                    const QStringList kValues{
                        kCleanTsvField(row.timestampText),
                        kCleanTsvField(row.providerName),
                        QString::number(row.eventId),
                        kCleanTsvField(row.eventName),
                        kCleanTsvField(row.pidTidText),
                        kCleanTsvField(row.detailSummary),
                        kCleanTsvField(row.activityId)
                    };
                    out << kValues.join(QChar(u'\t')) << QChar(u'\n');
                    ++exportedRows;
                    if (out.status() != QTextStream::Ok)
                    {
                        streamWriteFailed = true;
                        return false;
                    }
                    return true;
                };

                for (const QString& segmentPath : segmentPaths)
                {
                    if (kShouldCancel())
                    {
                        break;
                    }
                    if (!scanEtwArchiveFile(
                        segmentPath,
                        kRowVisitor,
                        kShouldCancel,
                        &scannedRows,
                        &maxSequence,
                        &errorText))
                    {
                        break;
                    }
                    if (streamWriteFailed)
                    {
                        errorText = QStringLiteral("写入 ETW 导出文件失败：%1").arg(kPath);
                        break;
                    }
                }
                out.flush();
                if (out.status() != QTextStream::Ok)
                {
                    errorText = QStringLiteral("写入 ETW 导出文件失败：%1").arg(kPath);
                }
            }

            bool committed = false;
            if (!kShouldCancel() && errorText.isEmpty())
            {
                committed = file.commit();
                if (!committed)
                {
                    errorText = QStringLiteral("提交 ETW 导出文件失败：%1").arg(kPath);
                }
            }
            else
            {
                file.cancelWriting();
            }
            if (kShouldCancel())
            {
                return;
            }

            QMetaObject::invokeMethod(qApp, [
                guardThis,
                kPath,
                exportedRows,
                scannedRows,
                committed,
                errorText]() {
                if (guardThis == nullptr)
                {
                    return;
                }
                if (!committed)
                {
                    QMessageBox::warning(
                        guardThis,
                        QStringLiteral("导出ETW"),
                        errorText.isEmpty() ? QStringLiteral("ETW 导出失败。") : errorText);
                    return;
                }

                KLogEvent event;
                info << event
                    << "[MonitorDock] ETW全量归档导出完成, path="
                    << kPath.toStdString()
                    << ", exportedRows="
                    << exportedRows
                    << ", scannedRows="
                    << scannedRows
                    << eol;
                QMessageBox::information(
                    guardThis,
                    QStringLiteral("导出ETW"),
                    QStringLiteral("导出完成：%1 条事件 -> %2")
                        .arg(static_cast<qulonglong>(exportedRows))
                        .arg(kPath));
            }, Qt::QueuedConnection);
        }).detach();
        return;
    }

    if (etwEventTable_ == nullptr || etwEventTable_->rowCount() == 0)
    {
        KLogEvent event;
        dbg << event
            << "[MonitorDock] ETW导出取消：无可导出事件。"
            << eol;
        QMessageBox::information(this, QStringLiteral("导出ETW"), QStringLiteral("当前没有可导出的事件。"));
        return;
    }

    int exportableCount = 0;
    for (int row = 0; row < etwEventTable_->rowCount(); ++row)
    {
        if (!visibleOnly || !etwEventTable_->isRowHidden(row))
        {
            ++exportableCount;
        }
    }
    if (exportableCount == 0)
    {
        KLogEvent event;
        dbg << event
            << "[MonitorDock] ETW导出取消：当前导出范围为空。"
            << eol;
        QMessageBox::information(this, QStringLiteral("导出ETW"), QStringLiteral("当前导出范围为空，没有可导出的ETW事件。"));
        return;
    }

    const QString kDefaultName = QStringLiteral("etw_events_%1.tsv")
        .arg(QDateTime::currentDateTime().toString(QStringLiteral("yyyyMMdd_HHmmss")));

    const QString kPath = QFileDialog::getSaveFileName(
        this,
        QStringLiteral("导出ETW结果"),
        kDefaultName,
        QStringLiteral("TSV文件 (*.tsv);;文本文件 (*.txt)"));

    if (kPath.trimmed().isEmpty())
    {
        KLogEvent event;
        dbg << event
            << "[MonitorDock] ETW导出取消：用户未选择路径。"
            << eol;
        return;
    }

    QFile file(kPath);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text | QIODevice::Truncate))
    {
        KLogEvent event;
        err << event
            << "[MonitorDock] ETW导出失败：无法写入文件, path="
            << kPath.toStdString()
            << eol;
        QMessageBox::warning(this, QStringLiteral("导出ETW"), QStringLiteral("无法写入文件：%1").arg(kPath));
        return;
    }

    QTextStream out(&file);

    QStringList header;
    for (int col = 0; col < etwEventTable_->columnCount(); ++col)
    {
        QTableWidgetItem* item = etwEventTable_->horizontalHeaderItem(col);
        header << (item != nullptr ? item->text() : QString());
    }
    out << header.join('\t') << '\n';

    for (int row = 0; row < etwEventTable_->rowCount(); ++row)
    {
        if (visibleOnly && etwEventTable_->isRowHidden(row))
        {
            continue;
        }

        QStringList values;
        for (int col = 0; col < etwEventTable_->columnCount(); ++col)
        {
            QTableWidgetItem* item = etwEventTable_->item(row, col);
            values << (item != nullptr ? item->text().replace('\t', ' ') : QString());
        }
        out << values.join('\t') << '\n';
    }

    file.close();

    KLogEvent event;
    info << event
        << "[MonitorDock] ETW导出完成:"
        << kPath.toStdString()
        << ", exportedRows="
        << exportableCount
        << ", visibleOnly="
        << (visibleOnly ? "true" : "false")
        << eol;
    QMessageBox::information(this, QStringLiteral("导出ETW"), QStringLiteral("导出完成：%1").arg(kPath));
}

void MonitorDock::openEtwEventDetailViewerForRow(const int row) const
{
    const QString kDetailText = buildEtwRowDetailText(etwEventTable_, row);
    if (kDetailText.trimmed().isEmpty())
    {
        return;
    }

    QString eventNameText;
    if (etwEventTable_ != nullptr)
    {
        QTableWidgetItem* eventNameItem = etwEventTable_->item(row, 3);
        if (eventNameItem != nullptr)
        {
            eventNameText = eventNameItem->text().trimmed();
        }
    }

    monitor_text_viewer::showReadOnlyTextWindow(
        const_cast<MonitorDock*>(this),
        QStringLiteral("ETW 返回详情 - %1").arg(eventNameText.isEmpty() ? QStringLiteral("事件") : eventNameText),
        kDetailText,
        QStringLiteral("monitor://etw/row-%1.txt").arg(row + 1));
}

void MonitorDock::showEtwEventContextMenu(const QPoint& position)
{
    const QModelIndex kIndex = etwEventTable_->indexAt(position);
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
            // Input: Current right-click row in the ETW event table.
            // Handling: Parse the PID from the PID/TID column and query the EXE path for that process.
            // Returns: The VT upload target; if parsing fails, a unified helper displays the error.
            QTableWidgetItem* pidItem = etwEventTable_ != nullptr
                ? etwEventTable_->item(kRow, 4)
                : nullptr;
            std::uint32_t pidValue = 0;
            if (pidItem == nullptr || !ks::online_scan::tryParsePidFromText(pidItem->text(), &pidValue))
            {
                return {
                    QString(),
                    QStringLiteral("ETW 事件"),
                    QStringLiteral("当前 ETW 事件行未解析出有效 PID，无法上传发起进程文件。")
                };
            }

            const QString kProcessPath = QString::fromStdString(ks::process::queryProcessPathByPid(pidValue)).trimmed();
            if (kProcessPath.isEmpty())
            {
                return {
                    QString(),
                    QStringLiteral("ETW 事件 PID=%1").arg(pidValue),
                    QStringLiteral("无法解析 PID=%1 的进程镜像路径。进程可能已退出，或当前权限不足。").arg(pidValue)
                };
            }

            return {
                kProcessPath,
                QStringLiteral("ETW 事件 PID=%1").arg(pidValue),
                QString()
            };
        });

    QAction* action = menu.exec(etwEventTable_->viewport()->mapToGlobal(position));
    if (action == nullptr)
    {
        KLogEvent event;
        dbg << event
            << "[MonitorDock] ETW事件右键菜单取消。"
            << eol;
        return;
    }

    if (action == viewDetailAction)
    {
        KLogEvent event;
        info << event
            << "[MonitorDock] ETW事件右键操作：查看返回详情, row="
            << kRow
            << eol;
        openEtwEventDetailViewerForRow(kRow);
        return;
    }

    if (action == copyDetailAction)
    {
        const QString kDetailText = buildEtwRowDetailText(etwEventTable_, kRow);
        QApplication::clipboard()->setText(kDetailText);
        KLogEvent event;
        dbg << event
            << "[MonitorDock] ETW事件右键操作：复制返回详情文本, row="
            << kRow
            << eol;
        return;
    }

    if (action == copyCellAction)
    {
        QTableWidgetItem* item = etwEventTable_->item(kRow, kCol);
        if (item != nullptr)
        {
            QApplication::clipboard()->setText(item->text());
        }
        KLogEvent event;
        dbg << event
            << "[MonitorDock] ETW事件右键操作：复制单元格, row="
            << kRow
            << ", col="
            << kCol
            << eol;
        return;
    }

    if (action == copyRowAction)
    {
        QStringList values;
        for (int i = 0; i < etwEventTable_->columnCount(); ++i)
        {
            QTableWidgetItem* item = etwEventTable_->item(kRow, i);
            values << (item != nullptr ? item->text() : QString());
        }
        QApplication::clipboard()->setText(values.join('\t'));
        KLogEvent event;
        dbg << event
            << "[MonitorDock] ETW事件右键操作：复制整行, row="
            << kRow
            << eol;
        return;
    }

    if (action == gotoProcessAction)
    {
        QTableWidgetItem* pidItem = etwEventTable_->item(kRow, 4);
        if (pidItem == nullptr)
        {
            return;
        }

        std::uint32_t pid = 0;
        if (!parsePid(pidItem->text(), pid))
        {
            KLogEvent event;
            warn << event
                << "[MonitorDock] ETW事件右键操作失败：PID解析失败, text="
                << pidItem->text().toStdString()
                << eol;
            QMessageBox::information(this, QStringLiteral("ETW事件"), QStringLiteral("未解析到有效PID。"));
            return;
        }
        KLogEvent event;
        info << event
            << "[MonitorDock] ETW事件右键操作：转到进程详情, pid="
            << pid
            << eol;
        openProcessDetail(this, pid);
    }
}

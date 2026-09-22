#include "FileDetailDialog.h"

namespace ksword::ui::file_dock
{
        void FileDetailDialog::setMetadataEditorBusy(const bool busy)
        {
            metadataEditorBusy_ = busy;
            const bool kEditorEnabled = metadataHasSnapshot_ && !busy;
            for (std::size_t timeIndex = 0; timeIndex < metadataTimeChecks_.size(); ++timeIndex)
            {
                if (metadataTimeChecks_[timeIndex] != nullptr)
                {
                    metadataTimeChecks_[timeIndex]->setEnabled(kEditorEnabled);
                }
                if (metadataTimeEdits_[timeIndex] != nullptr)
                {
                    const bool kTimeSelected = metadataTimeChecks_[timeIndex] != nullptr &&
                        metadataTimeChecks_[timeIndex]->isChecked();
                    metadataTimeEdits_[timeIndex]->setEnabled(kEditorEnabled && kTimeSelected);
                }
            }
            for (QCheckBox* const kAttributeCheck : metadataAttributeChecks_)
            {
                if (kAttributeCheck != nullptr)
                {
                    kAttributeCheck->setEnabled(kEditorEnabled);
                }
            }
            if (metadataRefreshButton_ != nullptr)
            {
                metadataRefreshButton_->setEnabled(!busy);
            }
            if (metadataApplyButton_ != nullptr)
            {
                metadataApplyButton_->setEnabled(kEditorEnabled);
            }
        }

        void FileDetailDialog::applyMetadataSnapshotToEditor(const FileMetadataSnapshot& snapshot)
        {
            if (!snapshot.ok)
            {
                return;
            }

            metadataApplyingSnapshot_ = true;
            metadataSnapshot_ = snapshot;
            metadataHasSnapshot_ = true;
            const std::array<LARGE_INTEGER, 4> kTimeValues = fileMetadataTimes(snapshot.basicInfo);
            for (std::size_t timeIndex = 0; timeIndex < kTimeValues.size(); ++timeIndex)
            {
                if (metadataTimeChecks_[timeIndex] != nullptr)
                {
                    metadataTimeChecks_[timeIndex]->setChecked(false);
                }
                if (metadataTimeEdits_[timeIndex] != nullptr)
                {
                    QDateTime dateTime = fileMetadataTimeToLocalDateTime(kTimeValues[timeIndex]);
                    if (!dateTime.isValid())
                    {
                        dateTime = QDateTime::currentDateTime();
                    }
                    metadataTimeEdits_[timeIndex]->setDateTime(dateTime);
                }
            }

            const auto& attributeMasks = editableFileAttributeMasks();
            for (std::size_t attributeIndex = 0;
                 attributeIndex < attributeMasks.size();
                 ++attributeIndex)
            {
                if (metadataAttributeChecks_[attributeIndex] != nullptr)
                {
                    metadataAttributeChecks_[attributeIndex]->setChecked(
                        (snapshot.basicInfo.FileAttributes & attributeMasks[attributeIndex]) != 0U);
                    metadataAttributeTouched_[attributeIndex] = false;
                }
            }
            metadataApplyingSnapshot_ = false;
            setMetadataEditorBusy(false);
        }

        FileDetailDialog::FileMetadataSnapshot FileDetailDialog::metadataSnapshotForEditor(
            const ks::file::metadata::FileSnapshot& snapshot)
        {
            FileMetadataSnapshot editorSnapshot;
            editorSnapshot.ok = snapshot.ok;
            editorSnapshot.win32Error = snapshot.win32Error;
            editorSnapshot.basicInfo = snapshot.basicInfo;
            editorSnapshot.identityAvailable = snapshot.identity.available;
            editorSnapshot.volumeSerialNumber = snapshot.identity.volumeSerialNumber;
            editorSnapshot.fileIndex = snapshot.identity.fileIndex;
            return editorSnapshot;
        }

        void FileDetailDialog::applyBatchMetadataSnapshotsToEditor(
            const QList<ks::file::metadata::FileSnapshot>& snapshots)
        {
            if (snapshots.isEmpty())
            {
                return;
            }
            applyMetadataSnapshotToEditor(metadataSnapshotForEditor(snapshots.front()));
            if (!batchMode_)
            {
                return;
            }

            metadataApplyingSnapshot_ = true;
            const auto& attributeMasks = editableFileAttributeMasks();
            for (std::size_t attributeIndex = 0;
                 attributeIndex < attributeMasks.size();
                 ++attributeIndex)
            {
                QCheckBox* const kAttributeCheck = metadataAttributeChecks_[attributeIndex];
                if (kAttributeCheck == nullptr)
                {
                    continue;
                }
                const DWORD kAttributeMask = attributeMasks[attributeIndex];
                const bool kFirstValue =
                    (snapshots.front().basicInfo.FileAttributes & kAttributeMask) != 0U;
                const bool kAllSame = std::all_of(
                    snapshots.cbegin(),
                    snapshots.cend(),
                    [kAttributeMask, kFirstValue](const ks::file::metadata::FileSnapshot& item)
                    {
                        return ((item.basicInfo.FileAttributes & kAttributeMask) != 0U) == kFirstValue;
                    });
                kAttributeCheck->setTristate(true);
                kAttributeCheck->setCheckState(
                    kAllSame
                        ? (kFirstValue ? Qt::Checked : Qt::Unchecked)
                        : Qt::PartiallyChecked);
                metadataAttributeTouched_[attributeIndex] = false;
            }
            metadataApplyingSnapshot_ = false;
        }

        void FileDetailDialog::refreshMetadataEditor()
        {
            if (metadataStatusLabel_ == nullptr || metadataEditorBusy_)
            {
                return;
            }

            if (pendingTargetCount() > 0)
            {
                QMessageBox::information(
                    this,
                    ks::i18n::sourceText(QStringLiteral("元数据编辑")),
                    ks::i18n::sourceText(QStringLiteral(
                        "存在尚未保存的暂存修改。请先保存或放弃暂存，再重新读取。")));
                return;
            }

            metadataHasSnapshot_ = false;
            setMetadataEditorBusy(true);
            metadataStatusLabel_->setText(
                ks::i18n::sourceText(QStringLiteral("● 正在后台读取文件元数据...")));
            const std::uint64_t kOperationGeneration = ++metadataOperationGeneration_;
            const QStringList kFilePathSnapshots = filePaths_;
            QPointer<FileDetailDialog> guardThis(this);
            auto* task = QRunnable::create([guardThis, kFilePathSnapshots, kOperationGeneration]()
                {
                    QList<ks::file::metadata::FileSnapshot> snapshots;
                    snapshots.reserve(kFilePathSnapshots.size());
                    for (const QString& filePath : kFilePathSnapshots)
                    {
                        snapshots.push_back(ks::file::metadata::readFileSnapshot(filePath));
                    }
                    FileDetailDialog* targetDialog = guardThis.data();
                    if (targetDialog == nullptr)
                    {
                        return;
                    }
                    QMetaObject::invokeMethod(
                        targetDialog,
                        [guardThis, snapshots, kFilePathSnapshots, kOperationGeneration]()
                        {
                            if (guardThis == nullptr ||
                                guardThis->metadataOperationGeneration_ != kOperationGeneration)
                            {
                                return;
                            }
                            QList<ks::file::metadata::FileSnapshot> successfulSnapshots;
                            QList<ks::file::metadata::TargetPatch> targetPatches;
                            int failedCount = 0;
                            DWORD firstError = ERROR_SUCCESS;
                            for (qsizetype index = 0; index < snapshots.size(); ++index)
                            {
                                const ks::file::metadata::FileSnapshot& snapshot = snapshots.at(index);
                                if (!snapshot.ok)
                                {
                                    ++failedCount;
                                    if (firstError == ERROR_SUCCESS) firstError = snapshot.win32Error;
                                    continue;
                                }
                                successfulSnapshots.push_back(snapshot);
                                ks::file::metadata::TargetPatch patch;
                                patch.originalPath = kFilePathSnapshots.value(index);
                                patch.snapshot = snapshot;
                                targetPatches.push_back(patch);
                            }

                            guardThis->pendingPatches_ = targetPatches;
                            guardThis->metadataHasSnapshot_ = !successfulSnapshots.isEmpty();
                            if (successfulSnapshots.isEmpty())
                            {
                                guardThis->setMetadataEditorBusy(false);
                                guardThis->metadataStatusLabel_->setText(
                                    ks::i18n::displayText(QStringLiteral("● 元数据读取失败：%1"))
                                        .arg(formatWin32ErrorText(firstError)));
                                guardThis->updatePendingSaveUi();
                                return;
                            }

                            guardThis->applyBatchMetadataSnapshotsToEditor(successfulSnapshots);
                            if (guardThis->metadataStatusLabel_ != nullptr)
                            {
                                guardThis->metadataStatusLabel_->setText(failedCount == 0
                                    ? ks::i18n::sourceText(QStringLiteral(
                                        "● 已读取 %1 个目标。编辑内容只会暂存，底部保存前文件不会变化。"))
                                        .arg(successfulSnapshots.size())
                                    : ks::i18n::sourceText(QStringLiteral(
                                        "● 已读取 %1 个目标，%2 个目标读取失败。失败目标不会进入保存事务。"))
                                        .arg(successfulSnapshots.size())
                                        .arg(failedCount));
                            }
                            guardThis->updatePendingSaveUi();
                        },
                        Qt::QueuedConnection);
                });
            task->setAutoDelete(true);
            QThreadPool::globalInstance()->start(task);
        }

        void FileDetailDialog::applyMetadataEditorChanges()
        {
            if (!metadataHasSnapshot_ || metadataEditorBusy_)
            {
                return;
            }

            const std::array<QString, 4> kTimeNames{
                QStringLiteral("创建时间"),
                QStringLiteral("最后访问时间"),
                QStringLiteral("最后写入时间"),
                QStringLiteral("元数据变更时间（ChangeTime）")
            };
            std::array<bool, 4> updateTime{};
            std::array<LARGE_INTEGER, 4> timeValues{};
            bool hasTimeChange = false;
            for (std::size_t timeIndex = 0; timeIndex < updateTime.size(); ++timeIndex)
            {
                if (metadataTimeChecks_[timeIndex] == nullptr ||
                    metadataTimeEdits_[timeIndex] == nullptr ||
                    !metadataTimeChecks_[timeIndex]->isChecked())
                {
                    continue;
                }
                const QDateTime kEditedDateTime = metadataTimeEdits_[timeIndex]->dateTime();
                if (!kEditedDateTime.isValid())
                {
                    QMessageBox::warning(
                        this,
                        ks::i18n::sourceText(QStringLiteral("元数据编辑")),
                        ks::i18n::sourceText(QStringLiteral("%1不是有效的日期时间。"))
                            .arg(ks::i18n::sourceText(kTimeNames[timeIndex])));
                    return;
                }
                updateTime[timeIndex] = true;
                timeValues[timeIndex] = localDateTimeToFileMetadataTime(kEditedDateTime);
                hasTimeChange = true;
            }

            const auto& attributeMasks = editableFileAttributeMasks();
            const bool kHasAttributeChange = std::any_of(
                metadataAttributeTouched_.cbegin(),
                metadataAttributeTouched_.cend(),
                [](const bool touched) { return touched; });
            if (!hasTimeChange && !kHasAttributeChange)
            {
                QMessageBox::information(
                    this,
                    ks::i18n::sourceText(QStringLiteral("元数据编辑")),
                    ks::i18n::sourceText(QStringLiteral("没有需要暂存的基础元数据改动。")));
                return;
            }

            for (ks::file::metadata::TargetPatch& patch : pendingPatches_)
            {
                patch.basic.updateTime = updateTime;
                patch.basic.timeValue = timeValues;
                patch.basic.updateAttributes = kHasAttributeChange;
                DWORD editableAttributes =
                    patch.snapshot.basicInfo.FileAttributes & editableFileAttributeMask();
                for (std::size_t attributeIndex = 0;
                     attributeIndex < attributeMasks.size();
                     ++attributeIndex)
                {
                    if (!metadataAttributeTouched_[attributeIndex] ||
                        metadataAttributeChecks_[attributeIndex] == nullptr)
                    {
                        continue;
                    }
                    if (metadataAttributeChecks_[attributeIndex]->checkState() == Qt::Checked)
                    {
                        editableAttributes |= attributeMasks[attributeIndex];
                    }
                    else
                    {
                        editableAttributes &= ~attributeMasks[attributeIndex];
                    }
                }
                patch.basic.editableAttributes = editableAttributes;
            }

            if (metadataStatusLabel_ != nullptr)
            {
                metadataStatusLabel_->setText(
                    ks::i18n::sourceText(QStringLiteral(
                        "● 基础元数据已暂存。点击窗口底部“保存全部修改”后才会写入文件。")));
            }
            updatePendingSaveUi();
        }

        QComboBox* FileDetailDialog::buildChangeStateCombo(QWidget* parent)
        {
            QComboBox* combo = new QComboBox(parent);
            combo->addItem(QStringLiteral("不修改"),
                static_cast<int>(ks::file::metadata::ChangeState::kUnchanged));
            combo->addItem(QStringLiteral("启用"),
                static_cast<int>(ks::file::metadata::ChangeState::kEnabled));
            combo->addItem(QStringLiteral("禁用"),
                static_cast<int>(ks::file::metadata::ChangeState::kDisabled));
            return combo;
        }

        ks::file::metadata::ChangeState FileDetailDialog::changeStateFromCombo(const QComboBox* combo)
        {
            return combo == nullptr
                ? ks::file::metadata::ChangeState::kUnchanged
                : static_cast<ks::file::metadata::ChangeState>(combo->currentData().toInt());
        }

        QByteArray FileDetailDialog::parseMetadataHexText(const QString& text, bool* okOut)
        {
            QString normalized = text;
            normalized.remove(QRegularExpression(QStringLiteral("[^0-9A-Fa-f]")));
            const bool kValid = (normalized.size() % 2) == 0;
            if (okOut != nullptr) *okOut = kValid;
            return kValid ? QByteArray::fromHex(normalized.toLatin1()) : QByteArray();
        }

        QByteArray FileDetailDialog::metadataEditorBytes(
            const QPlainTextEdit* editor,
            const QComboBox* formatCombo,
            bool* okOut)
        {
            if (editor == nullptr)
            {
                if (okOut != nullptr) *okOut = false;
                return {};
            }
            if (formatCombo != nullptr && formatCombo->currentIndex() == 1)
            {
                return parseMetadataHexText(editor->toPlainText(), okOut);
            }
            if (okOut != nullptr) *okOut = true;
            return editor->toPlainText().toUtf8();
        }

        void FileDetailDialog::refreshMetadataStreamTable(QTableWidget* table)
        {
            if (table == nullptr) return;
            table->setRowCount(0);
            const QStringList kPaths = filePaths_;
            QPointer<QTableWidget> tableGuard(table);
            auto* task = QRunnable::create([tableGuard, kPaths]()
                {
                    QList<QStringList> rows;
                    for (const QString& path : kPaths)
                    {
                        DWORD error = ERROR_SUCCESS;
                        const QList<ks::file::metadata::StreamEntry> kStreams =
                            ks::file::metadata::enumerateStreams(path, &error);
                        if (error != ERROR_SUCCESS)
                        {
                            rows.push_back(QStringList{
                                path,
                                QStringLiteral("<读取失败>"),
                                QString::number(error) });
                            continue;
                        }
                        for (const ks::file::metadata::StreamEntry& stream : kStreams)
                        {
                            rows.push_back(QStringList{
                                path,
                                stream.name,
                                QString::number(stream.size) });
                        }
                    }
                    if (tableGuard == nullptr) return;
                    QMetaObject::invokeMethod(tableGuard.data(), [tableGuard, rows]()
                        {
                            if (tableGuard == nullptr) return;
                            tableGuard->setRowCount(rows.size());
                            for (qsizetype row = 0; row < rows.size(); ++row)
                            {
                                const QStringList kValues = rows.at(row);
                                for (int column = 0; column < kValues.size(); ++column)
                                {
                                    tableGuard->setItem(static_cast<int>(row), column,
                                        new QTableWidgetItem(kValues.at(column)));
                                }
                            }
                        }, Qt::QueuedConnection);
                });
            task->setAutoDelete(true);
            QThreadPool::globalInstance()->start(task);
        }

        void FileDetailDialog::refreshMetadataEaTable(QTableWidget* table)
        {
            if (table == nullptr) return;
            table->setRowCount(0);
            const QStringList kPaths = filePaths_;
            QPointer<QTableWidget> tableGuard(table);
            auto* task = QRunnable::create([tableGuard, kPaths]()
                {
                    QList<QStringList> rows;
                    for (const QString& path : kPaths)
                    {
                        DWORD error = ERROR_SUCCESS;
                        const QList<ks::file::metadata::ExtendedAttributeEntry> kEntries =
                            ks::file::metadata::enumerateExtendedAttributes(path, &error);
                        if (error != ERROR_SUCCESS)
                        {
                            rows.push_back(QStringList{
                                path,
                                QStringLiteral("<读取失败>"),
                                QString::number(error),
                                QString() });
                            continue;
                        }
                        for (const ks::file::metadata::ExtendedAttributeEntry& entry : kEntries)
                        {
                            rows.push_back(QStringList{
                                path,
                                entry.name,
                                QString::number(entry.value.size()),
                                QString::fromLatin1(entry.value.left(64).toHex(' ').toUpper()) });
                        }
                    }
                    if (tableGuard == nullptr) return;
                    QMetaObject::invokeMethod(tableGuard.data(), [tableGuard, rows]()
                        {
                            if (tableGuard == nullptr) return;
                            tableGuard->setRowCount(rows.size());
                            for (qsizetype row = 0; row < rows.size(); ++row)
                            {
                                const QStringList kValues = rows.at(row);
                                for (int column = 0; column < kValues.size(); ++column)
                                {
                                    tableGuard->setItem(static_cast<int>(row), column,
                                        new QTableWidgetItem(kValues.at(column)));
                                }
                            }
                        }, Qt::QueuedConnection);
                });
            task->setAutoDelete(true);
            QThreadPool::globalInstance()->start(task);
        }
}

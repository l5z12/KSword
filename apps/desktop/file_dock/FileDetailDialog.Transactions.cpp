#include "FileDetailDialog.h"

namespace ksword::ui::file_dock
{
        int FileDetailDialog::pendingTargetCount() const
        {
            return static_cast<int>(std::count_if(
                pendingPatches_.cbegin(),
                pendingPatches_.cend(),
                [](const ks::file::metadata::TargetPatch& patch)
                {
                    return !patch.empty();
                }));
        }

        bool FileDetailDialog::ensurePendingPatchesForStaging()
        {
            if (!pendingPatches_.isEmpty())
            {
                return true;
            }
            QList<ks::file::metadata::TargetPatch> patches;
            for (const QString& path : filePaths_)
            {
                const ks::file::metadata::FileSnapshot kSnapshot =
                    ks::file::metadata::readFileSnapshot(path);
                if (!kSnapshot.ok)
                {
                    QMessageBox::warning(
                        this,
                        ks::i18n::sourceText(QStringLiteral("元数据编辑")),
                        ks::i18n::sourceText(QStringLiteral("无法读取目标快照：%1\n%2"))
                            .arg(QDir::toNativeSeparators(path))
                            .arg(formatWin32ErrorText(kSnapshot.win32Error)));
                    return false;
                }
                ks::file::metadata::TargetPatch patch;
                patch.originalPath = path;
                patch.snapshot = kSnapshot;
                patches.push_back(patch);
            }
            pendingPatches_ = patches;
            return !pendingPatches_.isEmpty();
        }

        int FileDetailDialog::pendingOperationCount() const
        {
            int count = 0;
            for (const ks::file::metadata::TargetPatch& patch : pendingPatches_)
            {
                if (patch.empty()) continue;
                if (patch.basic.updateAttributes ||
                    std::any_of(patch.basic.updateTime.cbegin(), patch.basic.updateTime.cend(),
                        [](const bool value) { return value; })) ++count;
                if (patch.rename) ++count;
                if (patch.setShortName) ++count;
                if (patch.caseSensitive != ks::file::metadata::ChangeState::kUnchanged) ++count;
                if (!patch.shellProperties.empty()) ++count;
                count += patch.streams.size();
                count += patch.extendedAttributes.size();
                if (!patch.security.empty()) ++count;
                if (patch.compression != ks::file::metadata::ChangeState::kUnchanged) ++count;
                if (patch.sparse != ks::file::metadata::ChangeState::kUnchanged) ++count;
                if (patch.encryption != ks::file::metadata::ChangeState::kUnchanged) ++count;
                if (patch.integrityStream != ks::file::metadata::ChangeState::kUnchanged) ++count;
                if (patch.objectId.update) ++count;
                count += patch.hardLinkPaths.size();
                if (patch.reparse.update) ++count;
                count += patch.peResources.size();
                if (patch.signatureDisposition ==
                    ks::file::metadata::SignatureDisposition::kRemoveEmbedded) ++count;
            }
            return count;
        }

        void FileDetailDialog::updatePendingSaveUi()
        {
            const int kTargetCount = pendingTargetCount();
            const int kOperationCount = pendingOperationCount();
            if (pendingChangesLabel_ != nullptr)
            {
                pendingChangesLabel_->setText(kTargetCount > 0
                    ? ks::i18n::sourceText(QStringLiteral(
                        "● 已暂存：%1 个目标，%2 类操作。文件尚未发生变化。"))
                        .arg(kTargetCount)
                        .arg(kOperationCount)
                    : ks::i18n::sourceText(QStringLiteral("● 暂无待保存修改")));
            }
            if (saveAllButton_ != nullptr)
            {
                saveAllButton_->setEnabled(kTargetCount > 0 && !transactionBusy_);
            }
            if (discardPendingButton_ != nullptr)
            {
                discardPendingButton_->setEnabled(kTargetCount > 0 && !transactionBusy_);
            }
        }

        void FileDetailDialog::resetPatchKeepingSnapshot(ks::file::metadata::TargetPatch& patch)
        {
            const QString kOriginalPath = patch.originalPath;
            const ks::file::metadata::FileSnapshot kSnapshot = patch.snapshot;
            patch = {};
            patch.originalPath = kOriginalPath;
            patch.snapshot = kSnapshot;
        }

        void FileDetailDialog::discardPendingChanges()
        {
            if (transactionBusy_)
            {
                return;
            }
            for (ks::file::metadata::TargetPatch& patch : pendingPatches_)
            {
                resetPatchKeepingSnapshot(patch);
            }
            metadataApplyingSnapshot_ = true;
            for (QCheckBox* const kTimeCheck : metadataTimeChecks_)
            {
                if (kTimeCheck != nullptr) kTimeCheck->setChecked(false);
            }
            metadataApplyingSnapshot_ = false;
            metadataAttributeTouched_.fill(false);
            if (metadataStatusLabel_ != nullptr)
            {
                metadataStatusLabel_->setText(
                    ks::i18n::sourceText(QStringLiteral("● 已放弃全部暂存修改，文件未发生变化。")));
            }
            updatePendingSaveUi();
            if (metadataHasSnapshot_)
            {
                QList<ks::file::metadata::FileSnapshot> snapshots;
                for (const ks::file::metadata::TargetPatch& patch : pendingPatches_)
                {
                    if (patch.snapshot.ok) snapshots.push_back(patch.snapshot);
                }
                applyBatchMetadataSnapshotsToEditor(snapshots);
            }
        }

        QString FileDetailDialog::transactionOperationText(const QString& operation)
        {
            if (operation == QStringLiteral("identity")) return QStringLiteral("身份复核");
            if (operation == QStringLiteral("backup")) return QStringLiteral("创建备份");
            if (operation == QStringLiteral("backup-required")) return QStringLiteral("备份要求");
            if (operation == QStringLiteral("basic")) return QStringLiteral("基础属性与时间");
            if (operation == QStringLiteral("rename")) return QStringLiteral("重命名");
            if (operation == QStringLiteral("short-name")) return QStringLiteral("8.3 短文件名");
            if (operation == QStringLiteral("case-sensitive")) return QStringLiteral("目录大小写敏感");
            if (operation == QStringLiteral("shell-properties")) return QStringLiteral("Shell 属性");
            if (operation.startsWith(QStringLiteral("ads:"))) return QStringLiteral("ADS：%1").arg(operation.mid(4));
            if (operation.startsWith(QStringLiteral("ea:"))) return QStringLiteral("EA：%1").arg(operation.mid(3));
            if (operation == QStringLiteral("security-sddl")) return QStringLiteral("安全描述符 SDDL");
            if (operation == QStringLiteral("security-ace")) return QStringLiteral("新增或修改 ACE");
            if (operation == QStringLiteral("security-remove-ace")) return QStringLiteral("删除 ACE");
            if (operation == QStringLiteral("compression")) return QStringLiteral("NTFS 压缩");
            if (operation == QStringLiteral("sparse")) return QStringLiteral("稀疏文件");
            if (operation == QStringLiteral("encryption")) return QStringLiteral("EFS 加密");
            if (operation == QStringLiteral("integrity-stream")) return QStringLiteral("Integrity Stream");
            if (operation == QStringLiteral("object-id")) return QStringLiteral("Object ID");
            if (operation.startsWith(QStringLiteral("hard-link:"))) return QStringLiteral("硬链接：%1").arg(operation.mid(10));
            if (operation == QStringLiteral("reparse")) return QStringLiteral("重解析点原始数据");
            if (operation == QStringLiteral("pe-resources")) return QStringLiteral("PE 资源");
            if (operation == QStringLiteral("signature-remove")) return QStringLiteral("清除嵌入式签名");
            if (operation == QStringLiteral("rollback")) return QStringLiteral("失败回滚");
            if (operation == QStringLiteral("readback")) return QStringLiteral("写后回读");
            return operation;
        }

        void FileDetailDialog::showTransactionResults(const ks::file::metadata::TransactionResult& result)
        {
            QDialog* dialog = new QDialog(this);
            dialog->setAttribute(Qt::WA_DeleteOnClose, true);
            dialog->setWindowTitle(ks::i18n::sourceText(QStringLiteral("文件元数据保存结果")));
            dialog->resize(1080, 560);
            QVBoxLayout* layout = new QVBoxLayout(dialog);

            QLabel* summaryLabel = new QLabel(result.ok
                ? ks::i18n::sourceText(QStringLiteral("● 全部目标保存并回读完成。"))
                : ks::i18n::sourceText(QStringLiteral(
                    "● 部分目标保存失败。失败目标已尽可能回滚，请查看逐操作结果。")),
                dialog);
            summaryLabel->setWordWrap(true);
            layout->addWidget(summaryLabel);

            QTableWidget* table = new ks::ui::VisibleTableWidget(dialog);
            table->setColumnCount(6);
            table->setHorizontalHeaderLabels(QStringList{
                QStringLiteral("目标"),
                QStringLiteral("操作"),
                QStringLiteral("结果"),
                QStringLiteral("错误"),
                QStringLiteral("详情"),
                QStringLiteral("备份") });
            table->setSelectionBehavior(QAbstractItemView::SelectRows);
            table->setSelectionMode(QAbstractItemView::ExtendedSelection);
            table->setEditTriggers(QAbstractItemView::NoEditTriggers);
            table->setAlternatingRowColors(true);
            int rowCount = 0;
            for (const ks::file::metadata::TargetResult& target : result.targets)
            {
                rowCount += target.operations.size();
            }
            table->setRowCount(rowCount);
            int row = 0;
            for (const ks::file::metadata::TargetResult& target : result.targets)
            {
                for (const ks::file::metadata::OperationResult& operation : target.operations)
                {
                    table->setItem(row, 0, new QTableWidgetItem(QDir::toNativeSeparators(target.originalPath)));
                    table->setItem(row, 1, new QTableWidgetItem(transactionOperationText(operation.operation)));
                    table->setItem(row, 2, new QTableWidgetItem(operation.ok
                        ? (operation.verified ? QStringLiteral("成功并验证") : QStringLiteral("成功，未验证"))
                        : QStringLiteral("失败")));
                    table->setItem(row, 3, new QTableWidgetItem(operation.ok
                        ? QStringLiteral("0")
                        : QStringLiteral("%1 · %2")
                            .arg(operation.win32Error)
                            .arg(formatWin32ErrorText(operation.win32Error))));
                    table->setItem(row, 4, new QTableWidgetItem(operation.detail));
                    table->setItem(row, 5, new QTableWidgetItem(QDir::toNativeSeparators(target.backupPath)));
                    ++row;
                }
            }
            installFileTableCopyMenu(table);
            if (table->horizontalHeader() != nullptr)
            {
                table->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
                table->horizontalHeader()->setStretchLastSection(true);
            }
            layout->addWidget(table, 1);
            QDialogButtonBox* buttons = new QDialogButtonBox(QDialogButtonBox::Close, dialog);
            connect(buttons, &QDialogButtonBox::rejected, dialog, &QDialog::close);
            layout->addWidget(buttons);
            dialog->show();
        }

        void FileDetailDialog::setTransactionBusy(const bool busy)
        {
            transactionBusy_ = busy;
            if (backupBeforeSaveCheck_ != nullptr) backupBeforeSaveCheck_->setEnabled(!busy);
            if (tabNavigation_ != nullptr) tabNavigation_->setEnabled(!busy);
            if (tabWidget_ != nullptr) tabWidget_->setEnabled(!busy);
            setMetadataEditorBusy(busy);
            updatePendingSaveUi();
        }

        void FileDetailDialog::saveAllPendingChanges()
        {
            if (transactionBusy_)
            {
                return;
            }
            QList<ks::file::metadata::TargetPatch> patches;
            for (const ks::file::metadata::TargetPatch& patch : pendingPatches_)
            {
                if (!patch.empty()) patches.push_back(patch);
            }
            if (patches.isEmpty())
            {
                return;
            }

            bool requiresBackup = false;
            bool signedTargetWillChange = false;
            bool hasCatalogSignature = false;
            for (const ks::file::metadata::TargetPatch& patch : patches)
            {
                requiresBackup = requiresBackup || patch.highRisk();
                if (!patch.snapshot.directory)
                {
                    const ks::file::metadata::SignatureInspection kSignature =
                        ks::file::metadata::inspectSignature(patch.originalPath);
                    signedTargetWillChange = signedTargetWillChange ||
                        kSignature.embedded || kSignature.catalog;
                    hasCatalogSignature = hasCatalogSignature || kSignature.catalog;
                }
            }
            if (requiresBackup &&
                (backupBeforeSaveCheck_ == nullptr || !backupBeforeSaveCheck_->isChecked()))
            {
                QMessageBox::warning(
                    this,
                    ks::i18n::sourceText(QStringLiteral("必须创建备份")),
                    ks::i18n::sourceText(QStringLiteral(
                        "暂存内容包含高风险操作。EA 原始数据、Object ID、重解析点、PE 资源和签名清除必须勾选“创建备份再修改”。")));
                return;
            }

            if (signedTargetWillChange)
            {
                QMessageBox signaturePrompt(this);
                signaturePrompt.setIcon(QMessageBox::Warning);
                signaturePrompt.setWindowTitle(
                    ks::i18n::sourceText(QStringLiteral("已签名文件将被修改")));
                signaturePrompt.setText(
                    ks::i18n::sourceText(QStringLiteral(
                        "修改已签名文件后，Authenticode 验证可能失效。请选择签名数据处理方式。")) +
                    (hasCatalogSignature
                        ? QLatin1Char('\n') + ks::i18n::sourceText(QStringLiteral(
                            "检测到 Catalog 签名。Catalog 只能显示失效状态，无法从文件本身删除。"))
                        : QString()));
                QPushButton* removeButton = signaturePrompt.addButton(
                    ks::i18n::sourceText(QStringLiteral("清除嵌入式签名并继续")),
                    QMessageBox::AcceptRole);
                QPushButton* preserveButton = signaturePrompt.addButton(
                    ks::i18n::sourceText(QStringLiteral("保留签名数据并继续")),
                    QMessageBox::DestructiveRole);
                QPushButton* cancelButton = signaturePrompt.addButton(
                    QMessageBox::Cancel);
                signaturePrompt.setDefaultButton(cancelButton);
                signaturePrompt.exec();
                if (signaturePrompt.clickedButton() == cancelButton)
                {
                    return;
                }
                if (signaturePrompt.clickedButton() == removeButton)
                {
                    for (ks::file::metadata::TargetPatch& patch : patches)
                    {
                        if (patch.snapshot.embeddedSignature)
                        {
                            patch.signatureDisposition =
                                ks::file::metadata::SignatureDisposition::kRemoveEmbedded;
                        }
                    }
                }
                else if (signaturePrompt.clickedButton() != preserveButton)
                {
                    return;
                }
            }

            requiresBackup = std::any_of(
                patches.cbegin(),
                patches.cend(),
                [](const ks::file::metadata::TargetPatch& patch) { return patch.highRisk(); });
            if (requiresBackup &&
                (backupBeforeSaveCheck_ == nullptr || !backupBeforeSaveCheck_->isChecked()))
            {
                QMessageBox::warning(
                    this,
                    ks::i18n::sourceText(QStringLiteral("必须创建备份")),
                    ks::i18n::sourceText(QStringLiteral(
                        "当前签名处理或高风险修改要求先创建备份。请勾选“创建备份再修改”。")));
                return;
            }

            const QMessageBox::StandardButton kConfirmation = QMessageBox::question(
                this,
                ks::i18n::sourceText(QStringLiteral("确认保存全部修改")),
                ks::i18n::sourceText(QStringLiteral(
                    "将保存 %1 个目标、%2 类暂存操作。保存前会重新校验文件身份，随后备份、写入并回读。是否继续？"))
                    .arg(patches.size())
                    .arg(pendingOperationCount()),
                QMessageBox::Yes | QMessageBox::No,
                QMessageBox::No);
            if (kConfirmation != QMessageBox::Yes)
            {
                return;
            }

            setTransactionBusy(true);
            if (pendingChangesLabel_ != nullptr)
            {
                pendingChangesLabel_->setText(
                    ks::i18n::sourceText(QStringLiteral("● 正在后台保存、回读并生成逐操作结果...")));
            }
            ks::file::metadata::TransactionOptions options;
            options.createBackup = backupBeforeSaveCheck_ != nullptr &&
                backupBeforeSaveCheck_->isChecked();
            QPointer<FileDetailDialog> guardThis(this);
            auto* task = QRunnable::create([guardThis, patches, options]()
                {
                    const ks::file::metadata::TransactionResult kResult =
                        ks::file::metadata::executeTransaction(patches, options);
                    if (guardThis == nullptr) return;
                    QMetaObject::invokeMethod(
                        guardThis.data(),
                        [guardThis, kResult]()
                        {
                            if (guardThis == nullptr) return;
                            QStringList updatedPaths = guardThis->filePaths_;
                            for (ks::file::metadata::TargetPatch& pendingPatch : guardThis->pendingPatches_)
                            {
                                const auto kResultIterator = std::find_if(
                                    kResult.targets.cbegin(),
                                    kResult.targets.cend(),
                                    [&pendingPatch](const ks::file::metadata::TargetResult& target)
                                    {
                                        return QDir::cleanPath(target.originalPath).compare(
                                            QDir::cleanPath(pendingPatch.originalPath),
                                            Qt::CaseInsensitive) == 0;
                                    });
                                if (kResultIterator == kResult.targets.cend() || !kResultIterator->ok)
                                {
                                    continue;
                                }
                                for (QString& path : updatedPaths)
                                {
                                    if (QDir::cleanPath(path).compare(
                                        QDir::cleanPath(pendingPatch.originalPath),
                                        Qt::CaseInsensitive) == 0)
                                    {
                                        path = kResultIterator->finalPath;
                                    }
                                }
                                pendingPatch = {};
                                pendingPatch.originalPath = kResultIterator->finalPath;
                                pendingPatch.snapshot = kResultIterator->finalSnapshot;
                            }
                            guardThis->filePaths_ = updatedPaths;
                            guardThis->filePath_ = updatedPaths.value(0);
                            guardThis->setTransactionBusy(false);
                            guardThis->showTransactionResults(kResult);
                            guardThis->updatePendingSaveUi();
                            if (kResult.ok)
                            {
                                guardThis->setWindowTitle(guardThis->batchMode_
                                    ? ks::i18n::sourceText(QStringLiteral("批量文件属性 - %1 项"))
                                        .arg(guardThis->filePaths_.size())
                                    : ks::i18n::displayText(QStringLiteral("文件属性 - %1"))
                                        .arg(QFileInfo(guardThis->filePath_).fileName()));
                                if (guardThis->metadataStatusLabel_ != nullptr)
                                {
                                    guardThis->metadataStatusLabel_->setText(
                                        ks::i18n::sourceText(QStringLiteral(
                                            "● 所有暂存修改已保存并完成写后回读。")));
                                }
                                guardThis->generalR0Loaded_ = false;
                                if (!guardThis->batchMode_)
                                {
                                    guardThis->refreshGeneralTab();
                                    const QFileInfo kRefreshedInfo(guardThis->filePath_);
                                    guardThis->startR0FileInfoLoad(
                                        kRefreshedInfo,
                                        guardThis->generalNtPathText_);
                                }
                            }
                        },
                        Qt::QueuedConnection);
                });
            task->setAutoDelete(true);
            QThreadPool::globalInstance()->start(task);
        }
}

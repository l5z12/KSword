#include "FileDetailDialog.h"

namespace ksword::ui::file_dock
{
        QWidget* FileDetailDialog::buildMetadataNameAndFilesystemPage(QWidget* parent)
        {
            QWidget* page = new QWidget(parent);
            QVBoxLayout* layout = new QVBoxLayout(page);
            QFormLayout* form = new QFormLayout();

            QCheckBox* renameCheck = new QCheckBox(QStringLiteral("暂存重命名"), page);
            QLineEdit* renameEdit = new QLineEdit(page);
            renameEdit->setText(batchMode_ ? QString() : QFileInfo(filePath_).fileName());
            renameEdit->setEnabled(!batchMode_);
            renameCheck->setEnabled(!batchMode_);
            form->addRow(renameCheck, renameEdit);

            QCheckBox* shortNameCheck = new QCheckBox(QStringLiteral("设置 8.3 短文件名"), page);
            QLineEdit* shortNameEdit = new QLineEdit(page);
            shortNameEdit->setPlaceholderText(QStringLiteral("例如 SAMPLE~1.TXT；留空可清除短名"));
            shortNameEdit->setEnabled(!batchMode_);
            shortNameCheck->setEnabled(!batchMode_);
            form->addRow(shortNameCheck, shortNameEdit);

            QComboBox* caseSensitiveCombo = buildChangeStateCombo(page);
            form->addRow(QStringLiteral("目录大小写敏感"), caseSensitiveCombo);
            QComboBox* compressionCombo = buildChangeStateCombo(page);
            form->addRow(QStringLiteral("NTFS 压缩"), compressionCombo);
            QComboBox* sparseCombo = buildChangeStateCombo(page);
            form->addRow(QStringLiteral("稀疏文件"), sparseCombo);
            QComboBox* encryptionCombo = buildChangeStateCombo(page);
            form->addRow(QStringLiteral("EFS 加密"), encryptionCombo);
            QComboBox* integrityCombo = buildChangeStateCombo(page);
            form->addRow(QStringLiteral("Integrity Stream"), integrityCombo);

            QComboBox* objectIdAction = new QComboBox(page);
            objectIdAction->addItems(QStringList{
                QStringLiteral("不修改"),
                QStringLiteral("设置 Object ID"),
                QStringLiteral("删除 Object ID") });
            QLineEdit* objectIdEdit = new QLineEdit(page);
            objectIdEdit->setPlaceholderText(QStringLiteral("16 字节或完整 64 字节十六进制"));
            QHBoxLayout* objectIdLayout = new QHBoxLayout();
            objectIdLayout->addWidget(objectIdAction);
            objectIdLayout->addWidget(objectIdEdit, 1);
            form->addRow(QStringLiteral("Object ID"), objectIdLayout);

            QPlainTextEdit* hardLinksEdit = new QPlainTextEdit(page);
            hardLinksEdit->setPlaceholderText(QStringLiteral("每行一个要创建的硬链接完整路径；仅单文件模式可用"));
            hardLinksEdit->setMaximumHeight(70);
            hardLinksEdit->setEnabled(!batchMode_);
            form->addRow(QStringLiteral("新增硬链接"), hardLinksEdit);
            layout->addLayout(form);

            QHBoxLayout* hardLinkQueryLayout = new QHBoxLayout();
            QPushButton* queryHardLinksButton = new QPushButton(QStringLiteral("枚举现有硬链接"), page);
            QLabel* hardLinkQueryResult = new QLabel(QStringLiteral("-"), page);
            hardLinkQueryResult->setTextInteractionFlags(Qt::TextSelectableByMouse);
            hardLinkQueryResult->setWordWrap(true);
            queryHardLinksButton->setEnabled(!batchMode_);
            hardLinkQueryLayout->addWidget(queryHardLinksButton);
            hardLinkQueryLayout->addWidget(hardLinkQueryResult, 1);
            layout->addLayout(hardLinkQueryLayout);

            QLabel* hint = new QLabel(QStringLiteral(
                "压缩、稀疏、EFS、Integrity Stream、Object ID 均通过公开 Win32/FSCTL 在 R3 完成。"
                "文件长度、有效数据长度、分配大小仍保持只读。"), page);
            hint->setWordWrap(true);
            layout->addWidget(hint);
            QPushButton* stageButton = new QPushButton(QStringLiteral("暂存名称与文件系统修改"), page);
            layout->addWidget(stageButton, 0, Qt::AlignRight);
            layout->addStretch(1);

            connect(queryHardLinksButton, &QPushButton::clicked, this,
                [this, hardLinkQueryResult]()
                {
                    DWORD error = ERROR_SUCCESS;
                    const QStringList kLinks = ks::file::metadata::enumerateHardLinks(filePath_, &error);
                    hardLinkQueryResult->setText(error == ERROR_SUCCESS
                        ? kLinks.join(QStringLiteral(" | "))
                        : QStringLiteral("枚举失败：%1").arg(formatWin32ErrorText(error)));
                });

            connect(stageButton, &QPushButton::clicked, this,
                [this, renameCheck, renameEdit, shortNameCheck, shortNameEdit,
                 caseSensitiveCombo, compressionCombo, sparseCombo, encryptionCombo,
                 integrityCombo, objectIdAction, objectIdEdit, hardLinksEdit]()
                {
                    if (!ensurePendingPatchesForStaging()) return;
                    QByteArray objectIdBytes;
                    if (objectIdAction->currentIndex() == 1)
                    {
                        bool objectIdOk = false;
                        objectIdBytes = parseMetadataHexText(objectIdEdit->text(), &objectIdOk);
                        if (!objectIdOk || (objectIdBytes.size() != 16 && objectIdBytes.size() != 64))
                        {
                            QMessageBox::warning(this, QStringLiteral("Object ID"),
                                QStringLiteral("Object ID 必须是 16 字节或完整 64 字节十六进制。"));
                            return;
                        }
                    }
                    const QStringList kHardLinkPaths = hardLinksEdit->toPlainText()
                        .split(QRegularExpression(QStringLiteral("[\\r\\n]+")), Qt::SkipEmptyParts);
                    for (ks::file::metadata::TargetPatch& patch : pendingPatches_)
                    {
                        patch.rename = !batchMode_ && renameCheck->isChecked();
                        patch.newName = renameEdit->text().trimmed();
                        patch.setShortName = !batchMode_ && shortNameCheck->isChecked();
                        patch.shortName = shortNameEdit->text().trimmed();
                        patch.caseSensitive = patch.snapshot.directory
                            ? changeStateFromCombo(caseSensitiveCombo)
                            : ks::file::metadata::ChangeState::kUnchanged;
                        patch.compression = changeStateFromCombo(compressionCombo);
                        patch.sparse = patch.snapshot.directory
                            ? ks::file::metadata::ChangeState::kUnchanged
                            : changeStateFromCombo(sparseCombo);
                        patch.encryption = changeStateFromCombo(encryptionCombo);
                        patch.integrityStream = changeStateFromCombo(integrityCombo);
                        patch.objectId.update = objectIdAction->currentIndex() != 0;
                        patch.objectId.remove = objectIdAction->currentIndex() == 2;
                        patch.objectId.objectId = objectIdBytes;
                        patch.hardLinkPaths = batchMode_ ? QStringList() : kHardLinkPaths;
                    }
                    updatePendingSaveUi();
                });
            return page;
        }

        QWidget* FileDetailDialog::buildMetadataShellPropertyPage(QWidget* parent)
        {
            QWidget* page = new QWidget(parent);
            QVBoxLayout* layout = new QVBoxLayout(page);
            QGridLayout* grid = new QGridLayout();
            struct ShellRow
            {
                QCheckBox* update = nullptr;
                QLineEdit* editor = nullptr;
            };
            const QStringList kLabels{
                QStringLiteral("标题"),
                QStringLiteral("主题"),
                QStringLiteral("作者（分号分隔）"),
                QStringLiteral("标签 / 关键字（分号分隔）"),
                QStringLiteral("注释"),
                QStringLiteral("版权") };
            std::array<ShellRow, 6> rows{};
            for (int index = 0; index < static_cast<int>(rows.size()); ++index)
            {
                rows[static_cast<std::size_t>(index)].update =
                    new QCheckBox(QStringLiteral("修改"), page);
                rows[static_cast<std::size_t>(index)].editor = new QLineEdit(page);
                grid->addWidget(rows[static_cast<std::size_t>(index)].update, index, 0);
                grid->addWidget(new QLabel(kLabels.at(index), page), index, 1);
                grid->addWidget(rows[static_cast<std::size_t>(index)].editor, index, 2);
            }
            QCheckBox* ratingCheck = new QCheckBox(QStringLiteral("修改"), page);
            QSpinBox* ratingSpin = new QSpinBox(page);
            ratingSpin->setRange(0, 99);
            grid->addWidget(ratingCheck, 6, 0);
            grid->addWidget(new QLabel(QStringLiteral("评分（0-99）"), page), 6, 1);
            grid->addWidget(ratingSpin, 6, 2);
            grid->setColumnStretch(2, 1);
            layout->addLayout(grid);

            QLabel* status = new QLabel(QStringLiteral("可从第一个目标读取当前 Shell 属性。"), page);
            status->setWordWrap(true);
            QHBoxLayout* actions = new QHBoxLayout();
            QPushButton* loadButton = new QPushButton(QStringLiteral("读取当前值"), page);
            QPushButton* stageButton = new QPushButton(QStringLiteral("暂存 Shell 属性"), page);
            actions->addWidget(loadButton);
            actions->addStretch(1);
            actions->addWidget(stageButton);
            layout->addWidget(status);
            layout->addLayout(actions);
            layout->addStretch(1);

            connect(loadButton, &QPushButton::clicked, this, [this, rows, ratingSpin, status]()
                {
                    status->setText(QStringLiteral("● 正在后台读取 Shell 属性..."));
                    const QString kPath = filePath_;
                    QPointer<FileDetailDialog> dialogGuard(this);
                    QPointer<QLabel> statusGuard(status);
                    auto* task = QRunnable::create([dialogGuard, statusGuard, kPath, rows, ratingSpin]()
                        {
                            const ks::file::metadata::ShellProperties kProperties =
                                ks::file::metadata::readShellProperties(kPath);
                            if (dialogGuard == nullptr) return;
                            QMetaObject::invokeMethod(dialogGuard.data(),
                                [dialogGuard, statusGuard, kProperties, rows, ratingSpin]()
                                {
                                    if (dialogGuard == nullptr || statusGuard == nullptr) return;
                                    if (!kProperties.ok)
                                    {
                                        statusGuard->setText(QStringLiteral("● Shell 属性读取失败：%1")
                                            .arg(formatWin32ErrorText(kProperties.win32Error)));
                                        return;
                                    }
                                    const QStringList kValues{
                                        kProperties.title,
                                        kProperties.subject,
                                        kProperties.authors.join(QStringLiteral("; ")),
                                        kProperties.keywords.join(QStringLiteral("; ")),
                                        kProperties.comment,
                                        kProperties.copyright };
                                    for (int index = 0; index < kValues.size(); ++index)
                                    {
                                        if (rows[static_cast<std::size_t>(index)].editor != nullptr)
                                        {
                                            rows[static_cast<std::size_t>(index)].editor->setText(kValues.at(index));
                                        }
                                    }
                                    ratingSpin->setValue(static_cast<int>(kProperties.rating));
                                    statusGuard->setText(QStringLiteral("● 已读取第一个目标的当前值。"));
                                }, Qt::QueuedConnection);
                        });
                    task->setAutoDelete(true);
                    QThreadPool::globalInstance()->start(task);
                });
            connect(stageButton, &QPushButton::clicked, this, [this, rows, ratingCheck, ratingSpin, status]()
                {
                    if (!ensurePendingPatchesForStaging()) return;
                    for (ks::file::metadata::TargetPatch& patch : pendingPatches_)
                    {
                        auto& shell = patch.shellProperties;
                        shell.updateTitle = rows[0].update->isChecked();
                        shell.title = rows[0].editor->text();
                        shell.updateSubject = rows[1].update->isChecked();
                        shell.subject = rows[1].editor->text();
                        shell.updateAuthors = rows[2].update->isChecked();
                        shell.authors = rows[2].editor->text().split(QLatin1Char(';'), Qt::SkipEmptyParts);
                        shell.updateKeywords = rows[3].update->isChecked();
                        shell.keywords = rows[3].editor->text().split(QLatin1Char(';'), Qt::SkipEmptyParts);
                        shell.updateComment = rows[4].update->isChecked();
                        shell.comment = rows[4].editor->text();
                        shell.updateCopyright = rows[5].update->isChecked();
                        shell.copyright = rows[5].editor->text();
                        shell.updateRating = ratingCheck->isChecked();
                        shell.rating = static_cast<quint32>(ratingSpin->value());
                    }
                    status->setText(QStringLiteral("● Shell 属性已暂存。"));
                    updatePendingSaveUi();
                });
            return page;
        }

        QWidget* FileDetailDialog::buildMetadataBasicPropertiesPage(QWidget* parent)
        {
            QWidget* page = new QWidget(parent);
            QVBoxLayout* layout = new QVBoxLayout(page);
            layout->setSpacing(10);

            QLabel* targetLabel = new QLabel(
                batchMode_
                    ? ks::i18n::sourceText(QStringLiteral("批量目标：%1 项"))
                        .arg(filePaths_.size())
                    : ks::i18n::sourceText(QStringLiteral("目标：%1"))
                        .arg(QDir::toNativeSeparators(filePath_)),
                page);
            targetLabel->setWordWrap(true);
            targetLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
            layout->addWidget(targetLabel);

            QLabel* hintLabel = new QLabel(
                ks::i18n::sourceText(QStringLiteral(
                    "时间按本地时区显示，精确到毫秒；只有勾选“修改”的时间字段才会写入。")) +
                QLatin1Char('\n') +
                ks::i18n::sourceText(QStringLiteral(
                    "属性编辑只开放可直接切换的位，目录、重解析点、压缩、加密、稀疏等结构性属性始终保留。")) +
                QLatin1Char('\n') +
                ks::i18n::sourceText(QStringLiteral(
                    "本页按钮只会暂存修改。窗口底部“保存全部修改”是唯一写入入口。")),
                page);
            hintLabel->setWordWrap(true);
            layout->addWidget(hintLabel);

            QGroupBox* timeGroup = new QGroupBox(QStringLiteral("文件时间"), page);
            QGridLayout* timeLayout = new QGridLayout(timeGroup);
            timeLayout->setColumnStretch(2, 1);
            timeLayout->addWidget(new QLabel(QStringLiteral("写入"), timeGroup), 0, 0);
            timeLayout->addWidget(new QLabel(QStringLiteral("字段"), timeGroup), 0, 1);
            timeLayout->addWidget(new QLabel(QStringLiteral("本地时间（含毫秒）"), timeGroup), 0, 2);

            const std::array<QString, 4> kTimeNames{
                QStringLiteral("创建时间"),
                QStringLiteral("最后访问时间"),
                QStringLiteral("最后写入时间"),
                QStringLiteral("元数据变更时间（ChangeTime）")
            };
            // Note: In FileBasicInformation, a value of 0 in the 'set' semantics means 'keep unchanged'; thus, selecting exactly the FILETIME
            // epoch of 1601-01-01 00:00:00 UTC is disallowed. Starting from the next day avoids the value becoming 0 after timezone conversion.
            const QDateTime kMinimumDateTime(QDate(1601, 1, 2), QTime(0, 0));
            const QDateTime kMaximumDateTime(QDate(9999, 12, 31), QTime(23, 59, 59, 999));
            for (std::size_t timeIndex = 0; timeIndex < kTimeNames.size(); ++timeIndex)
            {
                QCheckBox* modifyCheck = new QCheckBox(QStringLiteral("修改"), timeGroup);
                QDateTimeEdit* dateTimeEdit = new QDateTimeEdit(timeGroup);
                dateTimeEdit->setCalendarPopup(true);
                dateTimeEdit->setDisplayFormat(QStringLiteral("yyyy-MM-dd HH:mm:ss.zzz"));
                dateTimeEdit->setMinimumDateTime(kMinimumDateTime);
                dateTimeEdit->setMaximumDateTime(kMaximumDateTime);
                dateTimeEdit->setEnabled(false);
                metadataTimeChecks_[timeIndex] = modifyCheck;
                metadataTimeEdits_[timeIndex] = dateTimeEdit;
                timeLayout->addWidget(modifyCheck, static_cast<int>(timeIndex) + 1, 0);
                timeLayout->addWidget(
                    new QLabel(kTimeNames[timeIndex], timeGroup),
                    static_cast<int>(timeIndex) + 1,
                    1);
                timeLayout->addWidget(dateTimeEdit, static_cast<int>(timeIndex) + 1, 2);
                connect(modifyCheck, &QCheckBox::toggled, dateTimeEdit,
                    [this, dateTimeEdit](const bool checked)
                    {
                        dateTimeEdit->setEnabled(
                            checked && metadataHasSnapshot_ && !metadataEditorBusy_);
                    });
            }
            layout->addWidget(timeGroup);

            QGroupBox* attributeGroup = new QGroupBox(QStringLiteral("可编辑文件属性"), page);
            QGridLayout* attributeLayout = new QGridLayout(attributeGroup);
            const std::array<QString, 6> kAttributeNames{
                QStringLiteral("只读（READONLY）"),
                QStringLiteral("隐藏（HIDDEN）"),
                QStringLiteral("系统（SYSTEM）"),
                QStringLiteral("存档（ARCHIVE）"),
                QStringLiteral("临时（TEMPORARY）"),
                QStringLiteral("不建内容索引（NOT_CONTENT_INDEXED）")
            };
            for (std::size_t attributeIndex = 0;
                 attributeIndex < kAttributeNames.size();
                 ++attributeIndex)
            {
                QCheckBox* attributeCheck =
                    new QCheckBox(kAttributeNames[attributeIndex], attributeGroup);
                metadataAttributeChecks_[attributeIndex] = attributeCheck;
                attributeLayout->addWidget(
                    attributeCheck,
                    static_cast<int>(attributeIndex / 2),
                    static_cast<int>(attributeIndex % 2));
                connect(attributeCheck, &QCheckBox::checkStateChanged, this,
                    [this, attributeIndex](const Qt::CheckState state)
                    {
                        if (!metadataApplyingSnapshot_ && state != Qt::PartiallyChecked)
                        {
                            metadataAttributeTouched_[attributeIndex] = true;
                        }
                    });
            }
            layout->addWidget(attributeGroup);
            layout->addStretch(1);
            return page;
        }

        QTabWidget* FileDetailDialog::buildMetadataEditorTabs(QWidget* parent)
        {
            QTabWidget* tabs = new QTabWidget(parent);
            tabs->addTab(
                buildMetadataBasicPropertiesPage(tabs),
                ks::i18n::sourceText(QStringLiteral("基础属性")));
            tabs->addTab(buildMetadataNameAndFilesystemPage(tabs), QStringLiteral("名称与文件系统"));
            tabs->addTab(buildMetadataShellPropertyPage(tabs), QStringLiteral("Shell 属性"));
            tabs->addTab(buildMetadataAdsPage(tabs), QStringLiteral("ADS"));
            tabs->addTab(buildMetadataEaPage(tabs), QStringLiteral("EA"));
            tabs->addTab(buildMetadataSecurityPage(tabs), QStringLiteral("安全描述符"));
            tabs->addTab(buildMetadataPeAndReparsePage(tabs), QStringLiteral("重解析点 / PE / 签名"));
            return tabs;
        }

        QWidget* FileDetailDialog::buildMetadataTab()
        {
            QWidget* page = new QWidget(this);
            QVBoxLayout* layout = new QVBoxLayout(page);
            layout->addWidget(buildMetadataEditorTabs(page), 1);

            QHBoxLayout* actionLayout = new QHBoxLayout();
            metadataRefreshButton_ = new QPushButton(QStringLiteral("重新读取"), page);
            metadataApplyButton_ = new QPushButton(QStringLiteral("暂存基础修改"), page);
            actionLayout->addStretch(1);
            actionLayout->addWidget(metadataRefreshButton_);
            actionLayout->addWidget(metadataApplyButton_);
            layout->addLayout(actionLayout);

            metadataStatusLabel_ = new QLabel(QStringLiteral("● 等待读取文件元数据。"), page);
            metadataStatusLabel_->setWordWrap(true);
            layout->addWidget(metadataStatusLabel_);

            connect(metadataRefreshButton_, &QPushButton::clicked, this,
                [this]() { refreshMetadataEditor(); });
            connect(metadataApplyButton_, &QPushButton::clicked, this,
                [this]() { applyMetadataEditorChanges(); });

            metadataHasSnapshot_ = false;
            setMetadataEditorBusy(false);
            QMetaObject::invokeMethod(page, [this]() { refreshMetadataEditor(); }, Qt::QueuedConnection);
            return page;
        }
}

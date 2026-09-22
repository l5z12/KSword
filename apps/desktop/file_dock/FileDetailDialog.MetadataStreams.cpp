#include "FileDetailDialog.h"

namespace ksword::ui::file_dock
{
        QWidget* FileDetailDialog::buildMetadataAdsPage(QWidget* parent)
        {
            QWidget* page = new QWidget(parent);
            QVBoxLayout* layout = new QVBoxLayout(page);
            QTableWidget* table = new ks::ui::VisibleTableWidget(page);
            table->setColumnCount(3);
            table->setHorizontalHeaderLabels(QStringList{
                QStringLiteral("目标"), QStringLiteral("数据流"), QStringLiteral("字节数") });
            table->setSelectionBehavior(QAbstractItemView::SelectRows);
            table->setSelectionMode(QAbstractItemView::SingleSelection);
            table->setEditTriggers(QAbstractItemView::NoEditTriggers);
            installFileTableCopyMenu(table);
            layout->addWidget(table, 1);

            QGridLayout* editorLayout = new QGridLayout();
            QLineEdit* nameEdit = new QLineEdit(page);
            nameEdit->setPlaceholderText(QStringLiteral("例如 Zone.Identifier"));
            QComboBox* formatCombo = new QComboBox(page);
            formatCombo->addItems(QStringList{ QStringLiteral("文本 UTF-8"), QStringLiteral("十六进制") });
            QCheckBox* removeCheck = new QCheckBox(QStringLiteral("删除该数据流"), page);
            QPlainTextEdit* dataEdit = new QPlainTextEdit(page);
            dataEdit->setMaximumHeight(120);
            editorLayout->addWidget(new QLabel(QStringLiteral("流名称"), page), 0, 0);
            editorLayout->addWidget(nameEdit, 0, 1);
            editorLayout->addWidget(formatCombo, 0, 2);
            editorLayout->addWidget(removeCheck, 0, 3);
            editorLayout->addWidget(dataEdit, 1, 0, 1, 4);
            layout->addLayout(editorLayout);

            QGroupBox* zoneGroup = new QGroupBox(QStringLiteral("Zone.Identifier 结构化编辑"), page);
            QFormLayout* zoneLayout = new QFormLayout(zoneGroup);
            QSpinBox* zoneIdSpin = new QSpinBox(zoneGroup);
            zoneIdSpin->setRange(0, 4);
            zoneIdSpin->setValue(3);
            QLineEdit* referrerEdit = new QLineEdit(zoneGroup);
            QLineEdit* hostEdit = new QLineEdit(zoneGroup);
            QPushButton* buildZoneButton = new QPushButton(QStringLiteral("生成结构化内容"), zoneGroup);
            zoneLayout->addRow(QStringLiteral("ZoneId"), zoneIdSpin);
            zoneLayout->addRow(QStringLiteral("ReferrerUrl"), referrerEdit);
            zoneLayout->addRow(QStringLiteral("HostUrl"), hostEdit);
            zoneLayout->addRow(QString(), buildZoneButton);
            layout->addWidget(zoneGroup);

            QHBoxLayout* actions = new QHBoxLayout();
            QPushButton* refreshButton = new QPushButton(QStringLiteral("刷新数据流"), page);
            QPushButton* loadButton = new QPushButton(QStringLiteral("读取选中流"), page);
            QPushButton* stageButton = new QPushButton(QStringLiteral("暂存 ADS 操作"), page);
            actions->addWidget(refreshButton);
            actions->addWidget(loadButton);
            actions->addStretch(1);
            actions->addWidget(stageButton);
            layout->addLayout(actions);

            connect(refreshButton, &QPushButton::clicked, this,
                [this, table]() { refreshMetadataStreamTable(table); });
            connect(buildZoneButton, &QPushButton::clicked, this,
                [nameEdit, formatCombo, dataEdit, zoneIdSpin, referrerEdit, hostEdit]()
                {
                    nameEdit->setText(QStringLiteral("Zone.Identifier"));
                    formatCombo->setCurrentIndex(0);
                    QString content = QStringLiteral("[ZoneTransfer]\r\nZoneId=%1\r\n")
                        .arg(zoneIdSpin->value());
                    if (!referrerEdit->text().trimmed().isEmpty())
                        content += QStringLiteral("ReferrerUrl=%1\r\n").arg(referrerEdit->text().trimmed());
                    if (!hostEdit->text().trimmed().isEmpty())
                        content += QStringLiteral("HostUrl=%1\r\n").arg(hostEdit->text().trimmed());
                    dataEdit->setPlainText(content);
                });
            connect(loadButton, &QPushButton::clicked, this, [this, table, nameEdit, formatCombo, dataEdit]()
                {
                    const int kRow = table->currentRow();
                    if (kRow < 0 || table->item(kRow, 0) == nullptr || table->item(kRow, 1) == nullptr) return;
                    const QString kPath = table->item(kRow, 0)->text();
                    const QString kName = table->item(kRow, 1)->text();
                    nameEdit->setText(kName);
                    DWORD error = ERROR_SUCCESS;
                    const QByteArray kData = ks::file::metadata::readStream(kPath, kName, &error);
                    if (error != ERROR_SUCCESS)
                    {
                        QMessageBox::warning(this, QStringLiteral("ADS"),
                            QStringLiteral("读取数据流失败：%1").arg(formatWin32ErrorText(error)));
                        return;
                    }
                    const bool kPrintable = std::all_of(kData.cbegin(), kData.cend(), [](const char value)
                        {
                            const unsigned char kByte = static_cast<unsigned char>(value);
                            return kByte == '\r' || kByte == '\n' || kByte == '\t' || kByte >= 0x20U;
                        });
                    formatCombo->setCurrentIndex(kPrintable ? 0 : 1);
                    dataEdit->setPlainText(kPrintable
                        ? QString::fromUtf8(kData)
                        : QString::fromLatin1(kData.toHex(' ').toUpper()));
                });
            connect(stageButton, &QPushButton::clicked, this,
                [this, nameEdit, formatCombo, removeCheck, dataEdit]()
                {
                    if (!ensurePendingPatchesForStaging()) return;
                    QString name = nameEdit->text().trimmed();
                    if (name.startsWith(QLatin1Char(':'))) name.remove(0, 1);
                    if (name.endsWith(QStringLiteral(":$DATA"), Qt::CaseInsensitive)) name.chop(6);
                    if (name.isEmpty() || name.compare(QStringLiteral("$DATA"), Qt::CaseInsensitive) == 0)
                    {
                        QMessageBox::warning(this, QStringLiteral("ADS"),
                            QStringLiteral("默认数据流保持只读。请输入命名数据流名称。"));
                        return;
                    }
                    bool dataOk = true;
                    const QByteArray kData = removeCheck->isChecked()
                        ? QByteArray()
                        : metadataEditorBytes(dataEdit, formatCombo, &dataOk);
                    if (!dataOk)
                    {
                        QMessageBox::warning(this, QStringLiteral("ADS"), QStringLiteral("十六进制数据格式无效。"));
                        return;
                    }
                    for (ks::file::metadata::TargetPatch& patch : pendingPatches_)
                    {
                        patch.streams.erase(std::remove_if(patch.streams.begin(), patch.streams.end(),
                            [&name](const ks::file::metadata::NamedBinaryPatch& item)
                            {
                                return item.name.compare(name, Qt::CaseInsensitive) == 0;
                            }), patch.streams.end());
                        ks::file::metadata::NamedBinaryPatch stream;
                        stream.name = name;
                        stream.action = removeCheck->isChecked()
                            ? ks::file::metadata::BinaryPatchAction::kRemove
                            : ks::file::metadata::BinaryPatchAction::kReplace;
                        stream.data = kData;
                        patch.streams.push_back(stream);
                    }
                    updatePendingSaveUi();
                });
            QMetaObject::invokeMethod(page, [this, table]() { refreshMetadataStreamTable(table); },
                Qt::QueuedConnection);
            return page;
        }

        QWidget* FileDetailDialog::buildMetadataEaPage(QWidget* parent)
        {
            QWidget* page = new QWidget(parent);
            QVBoxLayout* layout = new QVBoxLayout(page);
            QTableWidget* table = new ks::ui::VisibleTableWidget(page);
            table->setColumnCount(4);
            table->setHorizontalHeaderLabels(QStringList{
                QStringLiteral("目标"), QStringLiteral("EA 名称"),
                QStringLiteral("字节数"), QStringLiteral("值预览") });
            table->setSelectionBehavior(QAbstractItemView::SelectRows);
            table->setSelectionMode(QAbstractItemView::SingleSelection);
            table->setEditTriggers(QAbstractItemView::NoEditTriggers);
            installFileTableCopyMenu(table);
            layout->addWidget(table, 1);

            QLineEdit* nameEdit = new QLineEdit(page);
            nameEdit->setPlaceholderText(QStringLiteral("EA 名称，最长 255 字节"));
            QComboBox* formatCombo = new QComboBox(page);
            formatCombo->addItems(QStringList{ QStringLiteral("文本 UTF-8"), QStringLiteral("十六进制") });
            QCheckBox* needEaCheck = new QCheckBox(QStringLiteral("FILE_NEED_EA"), page);
            QCheckBox* removeCheck = new QCheckBox(QStringLiteral("删除该 EA"), page);
            QPlainTextEdit* dataEdit = new QPlainTextEdit(page);
            dataEdit->setMaximumHeight(120);
            QHBoxLayout* header = new QHBoxLayout();
            header->addWidget(nameEdit, 1);
            header->addWidget(formatCombo);
            header->addWidget(needEaCheck);
            header->addWidget(removeCheck);
            layout->addLayout(header);
            layout->addWidget(dataEdit);

            QHBoxLayout* actions = new QHBoxLayout();
            QPushButton* refreshButton = new QPushButton(QStringLiteral("刷新 EA"), page);
            QPushButton* loadButton = new QPushButton(QStringLiteral("读取选中 EA"), page);
            QPushButton* stageButton = new QPushButton(QStringLiteral("暂存 EA 操作"), page);
            actions->addWidget(refreshButton);
            actions->addWidget(loadButton);
            actions->addStretch(1);
            actions->addWidget(stageButton);
            layout->addLayout(actions);
            connect(refreshButton, &QPushButton::clicked, this,
                [this, table]() { refreshMetadataEaTable(table); });
            connect(loadButton, &QPushButton::clicked, this,
                [this, table, nameEdit, formatCombo, dataEdit, needEaCheck]()
                {
                    const int kRow = table->currentRow();
                    if (kRow < 0 || table->item(kRow, 0) == nullptr || table->item(kRow, 1) == nullptr) return;
                    DWORD error = ERROR_SUCCESS;
                    const auto kEntries = ks::file::metadata::enumerateExtendedAttributes(
                        table->item(kRow, 0)->text(), &error);
                    const QString kName = table->item(kRow, 1)->text();
                    const auto kIterator = std::find_if(kEntries.cbegin(), kEntries.cend(),
                        [&kName](const ks::file::metadata::ExtendedAttributeEntry& item)
                        {
                            return item.name == kName;
                        });
                    if (error != ERROR_SUCCESS || kIterator == kEntries.cend())
                    {
                        QMessageBox::warning(this, QStringLiteral("EA"),
                            QStringLiteral("读取 EA 失败：%1").arg(formatWin32ErrorText(error)));
                        return;
                    }
                    nameEdit->setText(kIterator->name);
                    needEaCheck->setChecked(kIterator->needEa);
                    formatCombo->setCurrentIndex(1);
                    dataEdit->setPlainText(QString::fromLatin1(kIterator->value.toHex(' ').toUpper()));
                });
            connect(stageButton, &QPushButton::clicked, this,
                [this, nameEdit, formatCombo, dataEdit, needEaCheck, removeCheck]()
                {
                    if (!ensurePendingPatchesForStaging()) return;
                    const QString kName = nameEdit->text().trimmed();
                    if (kName.isEmpty() || kName.toUtf8().size() > 255)
                    {
                        QMessageBox::warning(this, QStringLiteral("EA"), QStringLiteral("EA 名称无效。"));
                        return;
                    }
                    bool dataOk = true;
                    const QByteArray kData = removeCheck->isChecked()
                        ? QByteArray()
                        : metadataEditorBytes(dataEdit, formatCombo, &dataOk);
                    if (!dataOk || kData.size() > 65535)
                    {
                        QMessageBox::warning(this, QStringLiteral("EA"),
                            QStringLiteral("EA 值必须是不超过 65535 字节的有效数据。"));
                        return;
                    }
                    for (ks::file::metadata::TargetPatch& patch : pendingPatches_)
                    {
                        patch.extendedAttributes.erase(
                            std::remove_if(patch.extendedAttributes.begin(), patch.extendedAttributes.end(),
                                [&kName](const ks::file::metadata::NamedBinaryPatch& item)
                                {
                                    return item.name.compare(kName, Qt::CaseInsensitive) == 0;
                                }),
                            patch.extendedAttributes.end());
                        ks::file::metadata::NamedBinaryPatch ea;
                        ea.name = kName;
                        ea.needEa = needEaCheck->isChecked();
                        ea.action = removeCheck->isChecked()
                            ? ks::file::metadata::BinaryPatchAction::kRemove
                            : ks::file::metadata::BinaryPatchAction::kReplace;
                        ea.data = kData;
                        patch.extendedAttributes.push_back(ea);
                    }
                    updatePendingSaveUi();
                });
            QMetaObject::invokeMethod(page, [this, table]() { refreshMetadataEaTable(table); },
                Qt::QueuedConnection);
            return page;
        }
}
